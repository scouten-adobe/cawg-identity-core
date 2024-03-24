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

// use c2pa::{Assertion, AssertionBase};
// use serde::{Serialize, Serializer};

use super::CredentialHolder;

/// An `IdentityAssertionBuilder` gathers together the necessary components
/// for an identity assertion. When added to a [`ManifestBuilder`],
/// it ensures that the proper data is added to the final C2PA Manifest.
pub struct IdentityAssertionBuilder {
    credential_holder: Box<dyn CredentialHolder>,
    // referenced_assertions: Vec<MumbleSomething>,
}

impl IdentityAssertionBuilder {
    pub fn for_credential_holder<H: CredentialHolder + 'static>(credential_holder: H) -> Self {
        Self {
            credential_holder: Box::new(credential_holder),
        }
    }
}

// impl AssertionBase for AssertionBuilder {
//     fn label(&self) -> &str {
//         self.credential_holder.label()
//     }

//     fn version(&self) -> Option<usize> {
//         None
//     }

//     fn to_assertion(&self) -> c2pa::Result<Assertion> {
//         unimplemented!();
//     }

//     fn from_assertion(_assertion: &Assertion) -> c2pa::Result<Self> {
//         unimplemented!();
//     }
// }

// impl Serialize for AssertionBuilder {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: Serializer,
//     {
//         // Since we can't have the signature yet, just write a placeholder
//         // for now.
//         let placeholder = vec![0; self.credential_holder.reserve_size()];
//         serializer.serialize_bytes(&placeholder)
//     }
// }
