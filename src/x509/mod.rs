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

//! Contains implementations of [`CredentialHolder`] and [`CredentialHandler`]
//! for the X.509/COSE credential types described as
/// specified in [§8.2, X.509 certificates and COSE signatures].
///
/// [`CredentialHolder`]: crate::builder::CredentialHolder
/// [`CredentialHandler`]: crate::CredentialHandler
/// [§8.2, X.509 certificates and COSE signatures]: https://creator-assertions.github.io/identity/1.0-draft/#_x_509_certificates_and_cose_signatures
use c2pa::{create_signer, SigningAlg};

use crate::{builder::CredentialHolder, SignerPayload};

/// An implementation of [`CredentialHolder`] that supports X.509
/// certificates as the credential and generates COSE signatures as
/// specified in [§8.2, X.509 certificates and COSE signatures].
///
/// [`CredentialHolder`]: crate::builder::CredentialHolder
/// [§8.2, X.509 certificates and COSE signatures]: https://creator-assertions.github.io/identity/1.0-draft/#_x_509_certificates_and_cose_signatures
pub struct X509CredentialHolder {
    signcert: Vec<u8>,
    pkey: Vec<u8>,
    alg: SigningAlg,
    tsa_url: Option<String>,
    reserve_size: usize,
}

impl X509CredentialHolder {
    /// Creates an [`X509CredentialHolder`] instance using signing certificate
    /// `signcert` and private key `pkey`.
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
        let temp_signer = create_signer::from_keys(&signcert, &pkey, alg, tsa_url.clone())?;

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
impl CredentialHolder for X509CredentialHolder {
    fn sig_type(&self) -> &'static str {
        "cawg.x509.cose"
    }

    fn reserve_size(&self) -> usize {
        self.reserve_size
    }

    async fn sign(&self, signer_payload: &SignerPayload) -> c2pa::Result<Vec<u8>> {
        let temp_signer =
            create_signer::from_keys(&self.signcert, &self.pkey, self.alg, self.tsa_url.clone())?;

        let mut sp: Vec<u8> = vec![];
        ciborium::into_writer(signer_payload, &mut sp).map_err(|_| c2pa::Error::ClaimEncoding)?;

        temp_signer.sign(&sp)
    }
}
