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

use c2pa::{Assertion, AssertionBase};
use serde::{Serialize, Serializer};

/// An `AssertionBuilder` gathers together the necessary components
/// for an identity assertion. When added to a [`ManifestBuilder`],
/// it ensures that the proper data is added to the final C2PA Manifest.
pub struct AssertionBuilder {
    credential_holder: Box<dyn CredentialHolder>,
    // referenced_assertions: Vec<MumbleSomthing>,
}

impl AssertionBuilder {
    pub fn for_credential_holder<H: CredentialHolder + 'static>(credential_holder: H) -> Self {
        Self {
            credential_holder: Box::new(credential_holder),
        }
    }
}

impl AssertionBase for AssertionBuilder {
    fn label(&self) -> &str {
        self.credential_holder.label()
    }

    fn version(&self) -> Option<usize> {
        None
    }

    fn to_assertion(&self) -> c2pa::Result<Assertion> {
        unimplemented!();
    }

    fn from_assertion(_assertion: &Assertion) -> c2pa::Result<Self> {
        unimplemented!();
    }
}

impl Serialize for AssertionBuilder {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Since we can't have the signature yet, just write a placeholder
        // for now.
        let placeholder = vec![0; self.credential_holder.reserve_size()];
        serializer.serialize_bytes(&placeholder)
    }
}

/// A `CredentialHolder` is able to generate a signature over the `tbs`
/// data structure on behalf of a credential holder.
///
/// Implementations of this trait will specialize based on the kind of
/// signature as specified in
/// [Credentials, signatures, and validation methods](https://creator-assertions.github.io/identity/1.0-draft/#_credentials_signatures_and_validation_methods)
/// from the CAWG Identity Assertion specification.
#[async_trait::async_trait]
pub trait CredentialHolder {
    /// Returns the designated label for this kind of credential.
    ///
    /// Labels designated in the CAWG Identity Assertion specification
    /// will have the prefix `cawg.identity.`. Any label not designed
    /// in the CAWG specification MUST NOT start with `cawg.` but are
    /// encouraged to contain the string `.identity.`.
    fn label(&self) -> &'static str;

    /// Returns the maximum expected size in bytes of the `signature`
    /// field for the identity assertion which will be subsequently
    /// returned by the [`sign`] function. Signing will fail if the
    /// subsequent signature is larger than this number of bytes.
    ///
    /// This function is called only if the file format requires use
    /// of the C2PA data hash assertion.
    fn reserve_size(&self) -> usize;

    /// Signs the `tbs` data structure on behalf of the credential holder.
    ///
    /// If successful, returns the exact binary content to be placed in
    /// the `signature` field for this identity assertion.
    ///
    /// The signature MUST NOT be larger than the size previously stated
    /// by the [`reserve_size`] function.
    async fn sign(&self, tbs: &[u8]) -> c2pa::Result<Vec<u8>>;
}

/// Naive implementation of [`CredentialHolder`] trait for
/// proof-of-concept/testing purposes.
///
/// NOT intended for production use.
pub struct NaiveCredentialHolder {}

#[async_trait::async_trait]
impl CredentialHolder for NaiveCredentialHolder {
    fn label(&self) -> &'static str {
        "INVALID.demo.credential"
    }

    fn reserve_size(&self) -> usize {
        10000
    }

    async fn sign(&self, tbs: &[u8]) -> c2pa::Result<Vec<u8>> {
        Ok(tbs.to_owned())
    }
}
