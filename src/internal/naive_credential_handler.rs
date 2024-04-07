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

//! Naive implementation of credential-handling traits for
//! proof-of-concept/testing purposes.
//!
//! Not suitable for production use.

use std::fmt::{Debug, Formatter};

use async_trait::async_trait;

use crate::{
    builder::CredentialHolder, identity_assertion::ValidationError, CredentialSubject,
    SignatureHandler, SignerPayload, ValidationResult,
};

pub(crate) struct NaiveCredentialHolder {}

#[async_trait]
impl CredentialHolder for NaiveCredentialHolder {
    fn sig_type(&self) -> &'static str {
        "INVALID.identity.naive_credential"
    }

    fn reserve_size(&self) -> usize {
        1000
    }

    async fn sign(&self, signer_payload: &SignerPayload) -> c2pa::Result<Vec<u8>> {
        // Naive implementation simply serializes SignerPayload
        // in CBOR format and calls it a "signature."
        let mut result: Vec<u8> = vec![];

        match ciborium::into_writer(signer_payload, &mut result) {
            Ok(()) => Ok(result),
            Err(_) => Err(c2pa::Error::ClaimEncoding),
        }
    }
}

pub(crate) struct NaiveSignatureHandler {}

#[async_trait]
impl SignatureHandler for NaiveSignatureHandler {
    async fn check_signature<'a>(
        &self,
        signer_payload: &SignerPayload,
        signature: &'a [u8],
    ) -> ValidationResult<Box<dyn CredentialSubject<'a>>> {
        let mut signer_payload_cbor: Vec<u8> = vec![];
        ciborium::into_writer(signer_payload, &mut signer_payload_cbor)
            .map_err(|_| ValidationError::UnexpectedError)?;

        if signer_payload_cbor != signature {
            Err(ValidationError::InvalidSignature)
        } else {
            Ok(Box::new(NaiveCredentialSubject {}))
        }
    }
}

pub(crate) struct NaiveCredentialSubject {}

impl<'a> CredentialSubject<'a> for NaiveCredentialSubject {
    fn display_name(&self) -> Option<String> {
        Some("Credential for internal testing purposes only".to_string())
    }

    fn is_trusted(&self) -> bool {
        false
    }
}

impl Debug for NaiveCredentialSubject {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.write_str("NaiveCredentialSubject (for internal testing purposes only)")
    }
}
