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

//! Contains implementations of [`CredentialHolder`] and [`SignatureHandler`]
//! for verifiable credential as specified in [§8.1, W3C verifiable credential].
//!
//! [`CredentialHolder`]: crate::builder::CredentialHolder
//! [`SignatureHandler`]: crate::SignatureHandler
//! [§8.1, W3C verifiable credential]: https://creator-assertions.github.io/identity/1.x-add-vc-v3/#_w3c_verifiable_credential_2

#![allow(unused)] // TEMPORARY while building

use std::fmt::{Debug, Formatter};

use async_trait::async_trait;
use c2pa::SigningAlg;

use crate::{
    builder::CredentialHolder, NamedActor, SignatureHandler, SignerPayload, ValidationError,
    ValidationResult,
};

/// An implementation of [`CredentialHolder`] that supports varying forms of
/// credentials and generates W3C verifiable credential as the identity
/// assertino signature as specified in [§8.1, W3C verifiable credential].
///
/// [`CredentialHolder`]: crate::builder::CredentialHolder
/// [§8.1, W3C verifiable credential]: https://creator-assertions.github.io/identity/1.x-add-vc-v3/#_w3c_verifiable_credential_2
pub struct CredentialIdentityAssertionIssuer {
    signcert: Vec<u8>,
    pkey: Vec<u8>,
    alg: SigningAlg,
    tsa_url: Option<String>,
    reserve_size: usize,
}

impl CredentialIdentityAssertionIssuer {
    /// Creates a [`CredentialIdentityAssertionIssuer`] instance using signing
    /// certificate `signcert` and private key `pkey`.
    ///
    /// It is recommended to provide the URL of a timestamp authority via
    /// `tsa_url`.
    pub fn from_keys(
        signcert: Vec<u8>,
        pkey: Vec<u8>,
        alg: SigningAlg,
        tsa_url: Option<String>,
    ) -> c2pa::Result<Self> {
        // Sadly, we can't cache the signer because `c2pa::Signer` doesn't
        // implement `Send`.
        let temp_signer = c2pa::create_signer::from_keys(&signcert, &pkey, alg, tsa_url.clone())?;

        Ok(Self {
            signcert,
            pkey,
            alg,
            tsa_url,
            reserve_size: temp_signer.reserve_size(),
        })
    }
}

#[async_trait::async_trait]
impl CredentialHolder for CredentialIdentityAssertionIssuer {
    fn sig_type(&self) -> &'static str {
        "cawg.x509.cose"
    }

    fn reserve_size(&self) -> usize {
        self.reserve_size
    }

    async fn sign(&self, signer_payload: &SignerPayload) -> c2pa::Result<Vec<u8>> {
        unimplemented!();
    }
}
