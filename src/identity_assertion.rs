// Copyright 2024 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

use std::{
    collections::HashSet,
    fmt::{Debug, Formatter},
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::{
    builder::IdentityAssertionBuilder, internal, internal::debug_byte_slice::DebugByteSlice,
};

/// This struct represents the raw content of the identity assertion.
///
/// Use [`IdentityAssertionBuilder`] and [`ManifestBuilder`] to
/// ensure correct construction of a new identity assertion.
///
/// [`IdentityAssertionBuilder`]: crate::builder::IdentityAssertionBuilder
/// [`ManifestBuilder`]: crate::builder::ManifestBuilder
#[derive(Deserialize, Serialize)]
pub struct IdentityAssertion {
    #[serde(skip)]
    builder: Option<IdentityAssertionBuilder>,

    signer_payload: SignerPayload,
    sig_type: String,

    #[serde(with = "serde_bytes")]
    signature: Vec<u8>,

    #[serde(with = "serde_bytes")]
    pad1: Vec<u8>,

    // Must use explicit ByteBuf here because #[serde(with = "serde_bytes")]
    // does not working if Option<Vec<u8>>.
    #[serde(skip_serializing_if = "Option::is_none")]
    pad2: Option<serde_bytes::ByteBuf>,
}

impl IdentityAssertion {
    pub(crate) fn from_builder(builder: IdentityAssertionBuilder) -> Self {
        let signer_payload = SignerPayload {
            referenced_assertions: vec![HashedUri {
                url: "self#jumbf=c2pa.assertions/c2pa.hash.to_be_determined".to_owned(),
                alg: None,
                hash: vec![0; 32],
            }],
        };

        let sig_type = builder.credential_holder.sig_type().to_owned();
        let signature = vec![0; builder.credential_holder.reserve_size()];

        Self {
            builder: Some(builder),
            signer_payload,
            sig_type,
            signature,
            pad1: vec![0; 32],
            // a bit of padding just in case
            pad2: None,
        }
    }

    pub(crate) async fn update_with_signature(
        &mut self,
        mut manifest_store: Vec<u8>,
        assertion_offset: usize,
        assertion_size: usize,
        claim: &internal::c2pa_parser::Claim,
    ) -> Option<Vec<u8>> {
        // Update TBS with actual assertion references.

        // TO DO: Update to respond correctly when identity assertions refer to each
        // other.
        for ref_assertion in self.signer_payload.referenced_assertions.iter_mut() {
            let claim_assertion =
                if ref_assertion.url == "self#jumbf=c2pa.assertions/c2pa.hash.to_be_determined" {
                    claim
                        .assertions
                        .iter()
                        .find(|a| a.url.starts_with("self#jumbf=c2pa.assertions/c2pa.hash."))
                } else {
                    claim.assertions.iter().find(|a| a.url == ref_assertion.url)
                }?;

            ref_assertion.url = claim_assertion.url.clone();
            ref_assertion.hash = claim_assertion.hash.clone();

            ref_assertion.alg = Some(
                match claim_assertion.alg.as_ref() {
                    Some(alg) => alg,
                    None => claim.alg.as_ref()?,
                }
                .clone(),
            );
        }

        self.signature = self
            .builder
            .as_ref()?
            .credential_holder
            .sign(&self.signer_payload)
            .await
            .ok()?;
        self.pad1 = vec![];

        let mut assertion_cbor: Vec<u8> = vec![];
        ciborium::into_writer(&self, &mut assertion_cbor).ok()?;

        if assertion_cbor.len() > assertion_size {
            // TO DO: Think about how to signal this in such a way that
            // the CredentialHolder implementor understands the problem.
            eprintln!("ERROR: Serialized assertion is {len} bytes, which exceeds the planned size of {assertion_size} bytes", len = assertion_cbor.len());

            return None;
        }

        self.pad1 = vec![0u8; assertion_size - assertion_cbor.len() - 15];

        assertion_cbor.clear();
        ciborium::into_writer(&self, &mut assertion_cbor).ok()?;

        self.pad2 = Some(ByteBuf::from(vec![
            0u8;
            assertion_size - assertion_cbor.len() - 6
        ]));

        assertion_cbor.clear();
        ciborium::into_writer(&self, &mut assertion_cbor).ok()?;

        // TO DO: See if this approach ever fails. IMHO it "should" work for all cases.
        assert_eq!(assertion_size, assertion_cbor.len());

        // Replace placeholder assertion content with signed version.
        manifest_store[assertion_offset..assertion_offset + assertion_size]
            .copy_from_slice(&assertion_cbor);

        Some(manifest_store)
    }

    /// Check the validity of the identity assertion.
    pub async fn validate<'a>(
        &'a self,
        manifest: &c2pa::Manifest,
    ) -> ValidationResult<IdentityAssertionReport<'a>> {
        self.check_padding()?;

        let signer_payload = self.check_signer_payload(manifest)?;

        // TO DO: Allow configuration of signature handler list.
        // For the moment, we only have the "naive" one. :-/

        if cfg!(test) {
            let nsh = crate::internal::naive_credential_handler::NaiveSignatureHandler {};
            let credential_subject = nsh.check_signature(signer_payload, &self.signature).await?;

            Ok(IdentityAssertionReport {
                signer_payload,
                sig_type: &self.sig_type,
                credential_subject,
            })
        } else {
            Err(ValidationError::UnknownSignatureType(
                self.sig_type.to_string(),
            ))
        }
    }

    /// Return the [`SignerPayload`] from this identity assertion
    /// but only if it meets the requirements as described in
    /// [§7. Validating the identity assertion].
    ///
    /// [§7. Validating the identity assertion]: https://creator-assertions.github.io/identity/1.0-draft/#_validating_the_identity_assertion
    pub(crate) fn check_signer_payload<'a>(
        &'a self,
        manifest: &c2pa::Manifest,
    ) -> ValidationResult<&'a SignerPayload> {
        self.signer_payload
            .check_against_manifest(manifest)
            .map(|_| &self.signer_payload)
    }

    /// Check that padding values are acceptable (i.e. all zero-value bytes).
    pub(crate) fn check_padding(&self) -> ValidationResult<()> {
        if !self.pad1.iter().all(|b| *b == 0) {
            return Err(ValidationError::InvalidPadding);
        }

        if let Some(pad2) = self.pad2.as_ref() {
            if !pad2.iter().all(|b| *b == 0) {
                return Err(ValidationError::InvalidPadding);
            }
        }

        Ok(())
    }
}

impl Debug for IdentityAssertion {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_struct("IdentityAssertion")
            .field("signer_payload", &self.signer_payload)
            .field("sig_type", &self.sig_type)
            .field("signature", &DebugByteSlice(&self.signature))
            .finish()
    }
}

/// The set of data to be signed by the credential holder.
#[derive(Clone, Debug, Deserialize, Eq, Serialize, PartialEq)]
pub struct SignerPayload {
    /// List of assertions referenced by this credential signature
    pub referenced_assertions: Vec<HashedUri>,
}

impl SignerPayload {
    fn check_against_manifest(&self, manifest: &c2pa::Manifest) -> ValidationResult<()> {
        // All assertions mentioned in referenced_assertions
        // also need to be referenced in the claim.

        for ref_assertion in self.referenced_assertions.iter() {
            if let Some(claim_assertion) = manifest
                .assertion_references()
                .find(|a| a.url() == ref_assertion.url)
            {
                if claim_assertion.hash() != ref_assertion.hash {
                    return Err(ValidationError::AssertionMismatch(
                        ref_assertion.url.to_owned(),
                    ));
                }
                if let Some(alg) = claim_assertion.alg().as_ref() {
                    if Some(alg) != ref_assertion.alg.as_ref() {
                        return Err(ValidationError::AssertionMismatch(
                            ref_assertion.url.to_owned(),
                        ));
                    }
                } else {
                    return Err(ValidationError::AssertionMismatch(
                        ref_assertion.url.to_owned(),
                    ));
                }
            } else {
                return Err(ValidationError::AssertionNotInClaim(
                    ref_assertion.url.to_owned(),
                ));
            }
        }

        // Ensure that a hard binding assertion is present.

        let ref_assertion_labels: Vec<String> = self
            .referenced_assertions
            .iter()
            .map(|ra| ra.url.to_owned())
            .collect();

        if !ref_assertion_labels.iter().any(|ra| {
            if let Some((_jumbf_prefix, label)) = ra.rsplit_once('/') {
                label.starts_with("c2pa.hash.")
            } else {
                false
            }
        }) {
            return Err(ValidationError::NoHardBindingAssertion);
        }

        // Make sure no assertion references are duplicated.

        let mut labels = HashSet::<String>::new();

        for label in &ref_assertion_labels {
            let label = label.clone();
            if labels.contains(&label) {
                return Err(ValidationError::MultipleAssertionReferenced(label));
            }
            labels.insert(label);
        }

        Ok(())
    }
}

/// A `SignatureHandler` can read one kind of signature from an identity
/// assertion, assess the validity of the signature, and return information
/// about the corresponding credential subject.
#[async_trait]
pub trait SignatureHandler {
    /// Check the signature, returning an instance of [`CredentialSubject`] if
    /// the signature is valid.
    async fn check_signature<'a>(
        &self,
        signer_payload: &SignerPayload,
        signature: &'a [u8],
    ) -> ValidationResult<Box<dyn CredentialSubject<'a>>>;
}

/// A `CredentialSubject` is the actor named by a signature in an identity
/// assertion.
pub trait CredentialSubject<'a>: Debug {
    /// Return the name of the subject suitable for user experience display.
    fn display_name(&self) -> Option<String>;

    /// Return `true` if the subject's credentials chain up to a suitable trust
    /// list for this kind of signature.
    fn is_trusted(&self) -> bool;
}

/// A `HashedUri` provides a reference to content available within the same
/// manifest store.
///
/// This is described in §8.3, “[URI References],” of the C2PA Technical
/// Specification.
///
/// [URI References]: https://c2pa.org/specifications/specifications/2.0/specs/C2PA_Specification.html#_uri_references
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct HashedUri {
    /// JUMBF URI reference
    pub url: String,

    /// A string identifying the cryptographic hash algorithm used to compute
    /// the hash
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,

    /// Byte string containing the hash value
    #[serde(with = "serde_bytes")]
    pub hash: Vec<u8>,
}

impl Debug for HashedUri {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_struct("HashedUri")
            .field("url", &self.url)
            .field("alg", &self.alg)
            .field("hash", &DebugByteSlice(&self.hash))
            .finish()
    }
}

/// Describes the ways in which a CAWG identity
/// assertion can fail validation as described in
/// [§7. Validating the identity assertion].
///
/// [§7. Validating the identity assertion]: https://creator-assertions.github.io/identity/1.0-draft/#_validating_the_identity_assertion
/// [`IdentityAssertion`]: crate::IdentityAssertion
#[derive(Clone, Debug, Eq, thiserror::Error, PartialEq)]
pub enum ValidationError {
    /// The named assertion could not be found in the claim.
    #[error("No assertion with the label {0:#?} in the claim")]
    AssertionNotInClaim(String),

    /// The named assertion exists in the claim, but the hash does not match.
    #[error("The assertion with the label {0:#?} is not the same as in the claim")]
    AssertionMismatch(String),

    /// The named assertion was referenced more than once in the identity
    /// assertion.
    #[error("The assertion with the label {0:#?} is referenced multiple times")]
    MultipleAssertionReferenced(String),

    /// No hard-binding assertion was referenced in the identity assertion.
    #[error("No hard binding assertion is referenced")]
    NoHardBindingAssertion,

    /// The `sig_type` field is not recognized.
    #[error("Unable to parse a signature of type {0:#?}")]
    UnknownSignatureType(String),

    /// The signature is not valid.
    #[error("Signature is invalid")]
    InvalidSignature,

    /// The `pad1` or `pad2` fields contain values other than 0x00 bytes.
    #[error("Invalid padding")]
    InvalidPadding,

    /// Unexpected error while parsing or validating the identity assertion.
    #[error("Unexpected error")]
    UnexpectedError,
}

/// Result type for validation operations.
pub type ValidationResult<T> = std::result::Result<T, ValidationError>;

/// This struct is returned when the data in an identity assertion is deemed
/// valid.
#[derive(Debug)]
pub struct IdentityAssertionReport<'a> {
    /// The data that was presented to the [`CredentialHolder`] for signature
    /// 
    /// [`CredentialHolder`]: crate::builder::CredentialHolder
    pub signer_payload: &'a SignerPayload,

    /// The designated signature type for this signature
    pub sig_type: &'a str,

    /// The subject of the [`CredentialHolder`]'s signature
    /// 
    /// [`CredentialHolder`]: crate::builder::CredentialHolder
    pub credential_subject: Box<dyn CredentialSubject<'a>>,
}
