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

    pub(crate) async fn update_with_signature(
        &self,
        manifest_store: Vec<u8>,
        _assertion_offset: usize,
        _assertion_size: usize,
        _claim: &crate::c2pa::Claim,
    ) -> Option<Vec<u8>> {
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
