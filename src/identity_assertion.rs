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

use std::fmt::{Debug, Formatter};

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

    #[allow(unused_variables)] // TEMPORARY while building
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
