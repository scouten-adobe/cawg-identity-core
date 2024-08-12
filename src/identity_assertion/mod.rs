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

#![allow(unused)] // TEMPORARY while refactoring

use std::fmt::{Debug, Formatter};

use chrono::{DateTime, FixedOffset};
use iref::UriBuf;
use non_empty_string::NonEmptyString;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::{
    builder::IdentityAssertionBuilder, internal, internal::debug_byte_slice::DebugByteSlice,
};

pub(crate) mod signer_payload;
use signer_payload::{HashedUri, SignerPayload};

pub(crate) mod signature_handler;
use signature_handler::SignatureHandler;

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
        let sig_type = builder.credential_holder.sig_type().to_owned();

        let signer_payload = SignerPayload {
            referenced_assertions: vec![HashedUri {
                url: "self#jumbf=c2pa.assertions/c2pa.hash.to_be_determined".to_owned(),
                alg: None,
                hash: vec![0; 32],
            }],
            sig_type,
        };

        let signature = vec![0; builder.credential_holder.reserve_size()];

        Self {
            builder: Some(builder),
            signer_payload,
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

            ref_assertion.url.clone_from(&claim_assertion.url);
            ref_assertion.hash.clone_from(&claim_assertion.hash);

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

        if cfg!(test) {
            // Allow "naive" signature handler when in unit-test mode.

            let nsh = crate::internal::naive_credential_handler::NaiveSignatureHandler {};
            if let Ok(named_actor) = nsh.check_signature(signer_payload, &self.signature).await {
                return Ok(IdentityAssertionReport {
                    signer_payload,
                    named_actor,
                });
            }
        }

        // TO DO: Allow configuration of signature handler list.
        // For now, we hard-code the VC/creator identity assertion signature handler.

        let vc_handler = crate::w3c_vc::CoseVcSignatureHandler {};
        if let Ok(named_actor) = vc_handler
            .check_signature(signer_payload, &self.signature)
            .await
        {
            return Ok(IdentityAssertionReport {
                signer_payload,
                named_actor,
            });
        }

        Err(ValidationError::UnknownSignatureType(
            self.signer_payload.sig_type.clone(),
        ))
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
            .field("signature", &DebugByteSlice(&self.signature))
            .finish()
    }
}

/// A `NamedActor` is the actor named by a signature in an identity
/// assertion.
pub trait NamedActor<'a>: Debug {
    /// Return the name of the subject suitable for user experience display.
    fn display_name(&self) -> Option<String>;

    /// Return `true` if the subject's credentials chain up to a suitable trust
    /// list for this kind of signature.
    fn is_trusted(&self) -> bool;
}

/// An implementation of `VerifiedIdentity` contains information about
/// the _named actor_ as verified by an _identity provider_ which could be
/// the _identity assertion generator_ or a service contacted by the _identity
/// assertion generator._
pub trait VerifiedIdentity {
    /// ## Verified identity type
    ///
    /// This property defines the type of verification that was performed by the
    /// _identity provider._
    fn type_(&self) -> VerifiedIdentityType;

    /// ## Display name
    ///
    /// This property MAY be present. If present, it will be a non-empty string
    /// defining the _named actor’s_ name as understood by the _identity
    /// provider._
    fn name(&self) -> Option<NonEmptyString> {
        None
    }

    /// ## User name
    ///
    /// This property MAY be present. If present, it will be a non-empty text
    /// string representing the _named actor’s_ user name as assigned by the
    /// _identity provider._
    fn username(&self) -> Option<NonEmptyString> {
        None
    }

    /// ## Address
    ///
    /// This property MAY be present. If present, it will be non-empty text
    /// string representing the _named actor’s_ cryptographic address as
    /// assigned by the _identity provider.
    fn address(&self) -> Option<NonEmptyString> {
        None
    }

    /// ## URI
    ///
    /// This property MAY be present. If present, it will be a valid URI which
    /// is the primary point of contact for the _named actor_ as assigned by the
    /// _identity provider._
    fn uri(&self) -> Option<UriBuf> {
        None
    }

    /// ## Identity verification date
    ///
    /// This property represents the date and time when the relationship between
    /// the _named actor_ and the _identity provider_ was verified by the
    /// _identity assertion generator._
    fn verified_at(&self) -> DateTime<FixedOffset>;

    // /// ## Identity provider details
    // ///
    // /// The `verifiedIdentities[?].provider` property MUST be an object and MUST
    // /// be present. It contains details about the _identity provider_ and the
    // /// identity verification process.
    // #[ld("cawg:provider")]
    // pub provider: IdentityProvider,
}

/// A `VerifiedIdentityType` contains information about the kind of identity
/// verification that was performed by the _identity provider._
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum VerifiedIdentityType {
    /// The _identity provider_ has verified one or more government-issued
    /// identity documents presented by the _named actor._
    DocumentVerification,

    /// The _identity provider_ is attesting to the _named actor’s_ membership
    /// in an organization. This could be a professional organization or an
    /// employment relationship.
    Affiliation,

    /// The _named actor_ has demonstrated control over an account (typically a
    /// social media account) hosted by the _identity provider._
    SocialMedia,

    /// The _named actor_ has demonstrated control over an account (typically a
    /// crypto-wallet) hosted by the _identity provider._
    CryptoWallet,

    /// Other string values MAY be used in `verifiedIdentities[?].type` with the
    /// understanding that they may not be well understood by _identity
    /// assertion consumers._ String values for `verifiedIdentities[?].type`
    /// that begin with the prefix `cawg.` are reserved for the use of the
    /// Creator Assertions Working Group and MUST NOT be used unless defined in
    /// a this or a future version of this specification.
    Other(NonEmptyString),
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

    /// The subject of the [`CredentialHolder`]'s signature
    ///
    /// [`CredentialHolder`]: crate::builder::CredentialHolder
    pub named_actor: Box<dyn NamedActor<'a>>,
}
