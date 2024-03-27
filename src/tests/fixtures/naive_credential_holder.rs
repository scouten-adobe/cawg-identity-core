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

use crate::{builder::CredentialHolder, Tbs};

/// Naive implementation of [`CredentialHolder`] trait for
/// proof-of-concept/testing purposes.
///
/// Not suitable for production use.
pub(crate) struct NaiveCredentialHolder {}

#[async_trait::async_trait]
impl CredentialHolder for NaiveCredentialHolder {
    fn sig_type(&self) -> &'static str {
        "INVALID.identity.naive_credential"
    }

    fn reserve_size(&self) -> usize {
        10000
    }

    async fn sign(&self, tbs: &Tbs) -> c2pa::Result<Vec<u8>> {
        // Naive implementation simply serializes Tbs
        // in CBOR format and calls it a "signature."
        let mut result: Vec<u8> = vec![];

        match ciborium::into_writer(tbs, &mut result) {
            Ok(()) => Ok(result),
            Err(_) => Err(c2pa::Error::ClaimEncoding),
        }
    }
}
