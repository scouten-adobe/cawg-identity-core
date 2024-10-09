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

//! Hopefully temporary implementation of COSE enveloped signatures
//! for W3C verifiable credentials.
//!
//! Based on reading [§3.3 With COSE] of [Securing Verifiable Credentials using
//! JOSE and COSE], candidate recommendation draft as of 05 July 2024.
//!
//! Quick-and-dirty adaptation from [`ssi` crate], which I hope will add its own
//! COSE support to replace this.
//!
//! [§3.3 With COSE]: https://www.w3.org/TR/vc-jose-cose/#securing-with-cose
//! [Securing Verifiable Credentials using JOSE and COSE]: https://www.w3.org/TR/vc-jose-cose/
//! [`ssi` crate]: https://github.com/spruceid/ssi/

// Adapted from https://github.com/spruceid/ssi/blob/main/crates/claims/crates/vc-jose-cose/src/jose/credential.rs

use std::borrow::Cow;

use coset::{CoseSign1Builder, HeaderBuilder, TaggedCborSerializable};
use iref::Uri;
use serde::Serialize;
use ssi_claims_core::{ClaimsValidity, DateTimeProvider, SignatureError, ValidateClaims};
use ssi_jwk::JWK;
use ssi_jws::{JwsPayload, JwsSigner};
use ssi_vc::{
    v2::{Credential, CredentialTypes, JsonCredential},
    MaybeIdentified,
};
use xsd_types::DateTimeStamp;

/// Payload of a COSE-secured Verifiable Credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CoseVc<T = JsonCredential>(pub T);

impl<T: Serialize> CoseVc<T> {
    /// Sign a COSE VC into a COSE enveloped verifiable credential.
    #[allow(dead_code)]
    pub async fn sign_into_cose(&self, signer: &JWK) -> Result<Vec<u8>, SignatureError> {
        let info = signer.fetch_info().await?;
        let payload_bytes = self.payload_bytes();

        // TO DO (#27): Remove panic.
        #[allow(clippy::unwrap_used)]
        let coset_alg = match signer.get_algorithm().unwrap() {
            ssi_jwk::Algorithm::EdDSA => coset::iana::Algorithm::EdDSA,
            ssi_alg => {
                unimplemented!("Add support for SSI alg {ssi_alg:?}")
            }
        };

        let mut protected = HeaderBuilder::new()
            .algorithm(coset_alg)
            .content_type("application/vc".to_owned())
            .build();

        if let Some(key_id) = info.key_id.as_ref() {
            protected.key_id = key_id.as_bytes().to_vec();
        }

        let sign1 = CoseSign1Builder::new()
            .protected(protected)
            .payload(payload_bytes.to_vec())
            .create_signature(b"", |pt| sign_bytes(signer, pt))
            .build();

        // TO DO (#27): Remove panic.
        #[allow(clippy::unwrap_used)]
        Ok(sign1.to_tagged_vec().unwrap())
    }
}

#[allow(dead_code)]
fn sign_bytes(signer: &JWK, payload: &[u8]) -> Vec<u8> {
    // Copied this function out of impl JWSSigner for JWK
    // to get rid of the async-ness, which isn't compatible
    // with the coset interface.

    // TO DO (#27): Remove panic.
    #[allow(clippy::unwrap_used)]
    let algorithm = signer.get_algorithm().unwrap();

    // TO DO (#27): Remove panic.
    #[allow(clippy::unwrap_used)]
    ssi_jws::sign_bytes(algorithm, payload, signer).unwrap()
}

/* NOT YET ...
impl<T: DeserializeOwned> CoseVc<T> {
    /// Decode a JOSE VC.
    pub fn decode(jws: &CompactJWS) -> Result<DecodedJWS<Self>, JoseDecodeError> {
        jws.to_decoded()?
            .try_map(|payload| serde_json::from_slice(&payload).map(Self))
            .map_err(Into::into)
    }
}
*/

impl CoseVc {
    /* NOT YET ...
    /// Decode a JOSE VC with an arbitrary credential type.
    pub fn decode_any(jws: &CompactJWS) -> Result<DecodedJWS<Self>, JoseDecodeError> {
        Self::decode(jws)
    }
    */
}

impl<T: Serialize> JwsPayload for CoseVc<T> {
    fn typ(&self) -> Option<&str> {
        Some("vc-ld+cose")
    }

    fn cty(&self) -> Option<&str> {
        Some("vc")
    }

    fn payload_bytes(&self) -> Cow<[u8]> {
        // TO DO (#27): Remove panic.
        #[allow(clippy::unwrap_used)]
        Cow::Owned(serde_json::to_vec(&self.0).unwrap())
    }
}

/* NOT YET ...
impl<E, T> ValidateJWSHeader<E> for CoseVc<T> {
    fn validate_jws_header(&self, _env: &E, _header: &ssi_jws::Header) -> ClaimsValidity {
        // There are no formal obligations about `typ` and `cty`.
        // It SHOULD be `vc-ld+jwt` and `vc`, but it does not MUST.
        Ok(())
    }
}
*/

impl<T: MaybeIdentified> MaybeIdentified for CoseVc<T> {
    fn id(&self) -> Option<&Uri> {
        self.0.id()
    }
}

impl<T: Credential> Credential for CoseVc<T> {
    type Description = T::Description;
    type Evidence = T::Evidence;
    type Issuer = T::Issuer;
    type RefreshService = T::RefreshService;
    type RelatedResource = T::RelatedResource;
    type Schema = T::Schema;
    type Status = T::Status;
    type Subject = T::Subject;
    type TermsOfUse = T::TermsOfUse;

    fn id(&self) -> Option<&Uri> {
        Credential::id(&self.0)
    }

    fn additional_types(&self) -> &[String] {
        self.0.additional_types()
    }

    fn types(&self) -> CredentialTypes {
        self.0.types()
    }

    fn name(&self) -> Option<&str> {
        self.0.name()
    }

    fn description(&self) -> Option<&Self::Description> {
        self.0.description()
    }

    fn credential_subjects(&self) -> &[Self::Subject] {
        self.0.credential_subjects()
    }

    fn issuer(&self) -> &Self::Issuer {
        self.0.issuer()
    }

    fn valid_from(&self) -> Option<DateTimeStamp> {
        self.0.valid_from()
    }

    fn valid_until(&self) -> Option<DateTimeStamp> {
        self.0.valid_until()
    }

    fn credential_status(&self) -> &[Self::Status] {
        self.0.credential_status()
    }

    fn credential_schemas(&self) -> &[Self::Schema] {
        self.0.credential_schemas()
    }

    fn related_resources(&self) -> &[Self::RelatedResource] {
        self.0.related_resources()
    }

    fn refresh_services(&self) -> &[Self::RefreshService] {
        self.0.refresh_services()
    }

    fn terms_of_use(&self) -> &[Self::TermsOfUse] {
        self.0.terms_of_use()
    }

    fn evidence(&self) -> &[Self::Evidence] {
        self.0.evidence()
    }

    fn validate_credential<E>(&self, env: &E) -> ClaimsValidity
    where
        E: DateTimeProvider,
    {
        self.0.validate_credential(env)
    }
}

impl<E, P, T: ValidateClaims<E, P>> ValidateClaims<E, P> for CoseVc<T> {
    fn validate_claims(&self, environment: &E, proof: &P) -> ClaimsValidity {
        self.0.validate_claims(environment, proof)
    }
}
