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

#![allow(dead_code)] // TEMPORARY while building
#![allow(missing_docs)] // TEMPORARY while building

use c2pa::{Assertion, AssertionBase, AssertionCbor};
use serde::{Deserialize, Serialize};

use super::CredentialHolder;
use crate::{c2pa::HashedUri, Tbs};

/// An `IdentityAssertionBuilder` gathers together the necessary components
/// for an identity assertion. When added to a [`ManifestBuilder`],
/// it ensures that the proper data is added to the final C2PA Manifest.
///
/// [`ManifestBuilder`]: crate::builder::ManifestBuilder
pub struct IdentityAssertionBuilder {
    credential_holder: Box<dyn CredentialHolder>,
    // referenced_assertions: Vec<MumbleSomething>,
}

impl IdentityAssertionBuilder {
    pub fn for_credential_holder<CH: CredentialHolder + 'static>(credential_holder: CH) -> Self {
        Self {
            credential_holder: Box::new(credential_holder),
        }
    }
}

/// This struct is used behind the scenes to create both the placeholder
/// and the final versions of the identity assertion. It is intentionally
/// not part of the public API surface.
#[derive(Deserialize, Serialize)]
pub(crate) struct IdentityAssertion {
    #[serde(skip)]
    builder: Option<IdentityAssertionBuilder>,

    tbs: Tbs,
    sig_type: String,
    signature: Vec<u8>,
    pad1: Vec<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pad2: Option<Vec<u8>>,
}

impl IdentityAssertion {
    pub(crate) fn from_builder(builder: IdentityAssertionBuilder) -> Self {
        let tbs = Tbs {
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
            tbs,
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
        manifest_store: Vec<u8>,
        assertion_offset: usize,
        assertion_size: usize,
        claim: &crate::c2pa::Claim,
    ) -> Option<Vec<u8>> {
        // Update TBS with actual assertion references.

        // TO DO: Update to respond correctly when identity assertions refer to each
        // other.
        for ref_assertion in self.tbs.referenced_assertions.iter_mut() {
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
            .sign(&self.tbs)
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

        self.pad2 = Some(vec![0u8; assertion_size - assertion_cbor.len() - 6]);

        assertion_cbor.clear();
        ciborium::into_writer(&self, &mut assertion_cbor).ok()?;

        // TO DO: See if this approach ever fails. IMHO it "should" work for all cases.
        assert_eq!(assertion_size, assertion_cbor.len());

        Some(manifest_store)
    }
}

impl AssertionBase for IdentityAssertion {
    const LABEL: &'static str = "cawg.identity";
    const VERSION: Option<usize> = None;

    fn to_assertion(&self) -> c2pa::Result<Assertion> {
        self.to_cbor_assertion()
    }

    fn from_assertion(_assertion: &Assertion) -> c2pa::Result<Self> {
        unimplemented!();
    }
}

impl AssertionCbor for IdentityAssertion {}
