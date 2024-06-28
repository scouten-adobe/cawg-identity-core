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
//! for the X.509/COSE credential types described as specified in [§8.2, X.509
//! certificates and COSE signatures].
//!
//! [`CredentialHolder`]: crate::builder::CredentialHolder
//! [`SignatureHandler`]: crate::SignatureHandler
//! [§8.2, X.509 certificates and COSE signatures]: https://creator-assertions.github.io/identity/1.0-draft/#_x_509_certificates_and_cose_signatures
use std::fmt::{Debug, Formatter};

use async_trait::async_trait;
use c2pa::{
    cose_sign::cose_sign, cose_validator::verify_cose, status_tracker::OneShotStatusTracker,
    trust_handler::TrustHandlerConfig, validator::ValidationInfo, SigningAlg,
};

use crate::{
    builder::CredentialHolder, NamedActor, SignatureHandler, SignerPayload, ValidationError,
    ValidationResult,
};

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
impl CredentialHolder for X509CredentialHolder {
    fn sig_type(&self) -> &'static str {
        "cawg.x509.cose"
    }

    fn reserve_size(&self) -> usize {
        self.reserve_size
    }

    async fn sign(&self, signer_payload: &SignerPayload) -> c2pa::Result<Vec<u8>> {
        let temp_signer = c2pa::create_signer::from_keys(
            &self.signcert,
            &self.pkey,
            self.alg,
            self.tsa_url.clone(),
        )?;

        let mut sp: Vec<u8> = vec![];
        ciborium::into_writer(signer_payload, &mut sp).map_err(|_| c2pa::Error::ClaimEncoding)?;

        cose_sign(temp_signer.as_ref(), &sp, None)
    }
}

/// An implementation of [`SignatureHandler`] that supports COSE signatures
/// derived from X.509 certificates as specified in [§8.2, X.509 certificates
/// and COSE signatures].
///
/// [`SignatureHandler`]: crate::SignatureHandler
/// [§8.2, X.509 certificates and COSE signatures]: https://creator-assertions.github.io/identity/1.0-draft/#_x_509_certificates_and_cose_signatures
pub struct X509CoseSignatureHandler {}

#[async_trait]
impl SignatureHandler for X509CoseSignatureHandler {
    fn can_handle_sig_type(sig_type: &str) -> bool {
        sig_type == "cawg.x509.cose"
    }

    async fn check_signature<'a>(
        &self,
        signer_payload: &SignerPayload,
        signature: &'a [u8],
    ) -> ValidationResult<Box<dyn NamedActor<'a>>> {
        // MAJOR TO DO (POSSIBLE SPEC REVISION): Need to ensure
        // that the signer_payload we're verifying against is
        // byte-for-byte identical with what was used for signature.
        // Current implementation glosses over this.

        let mut signer_payload_cbor: Vec<u8> = vec![];
        ciborium::into_writer(signer_payload, &mut signer_payload_cbor)
            .map_err(|_| ValidationError::UnexpectedError)?;

        // -- FROM C2PA CLAIM VALIDATION --
        // // Parse COSE signed data (signature) and validate it.
        // let sig = claim.signature_val().clone();
        // let additional_bytes: Vec<u8> = Vec::new();
        // let claim_data = claim.data()?;

        let additional_data: Vec<u8> = vec![];

        // TO DO: Allow config of TrustHandler.
        let mut trust_handler = c2pa::openssl::OpenSSLTrustHandlerConfig::new();

        // TO DO: Allow config of StatusTracker.
        let mut status_tracker = OneShotStatusTracker::new();

        let verified = verify_cose(
            signature,
            &signer_payload_cbor,
            &additional_data,
            false,
            &mut trust_handler,
            &mut status_tracker,
        )
        .unwrap();
        // TO DO: Error handling.

        // dbg!(&verified);

        Ok(Box::new(X509NamedActor(verified)))
    }
}

/// An implementation of [`NamedActor`] that describes the subject of an X.509
/// credential.
///
/// [`NamedActor`]: crate::NamedActor
pub struct X509NamedActor(ValidationInfo);

impl<'a> NamedActor<'a> for X509NamedActor {
    fn display_name(&self) -> Option<String> {
        self.0.issuer_org.clone()
    }

    fn is_trusted(&self) -> bool {
        false
        // todo!("Is this on trust list?");
    }
}

impl Debug for X509NamedActor {
    fn fmt(&self, _f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        unimplemented!();
    }
}
