// Adapted from https://github.com/spruceid/ssi/blob/main/crates/claims/crates/vc-jose-cose/src/jose/credential.rs

use std::borrow::Cow;

use coset::{iana, CborSerializable, CoseSign1Builder, HeaderBuilder};
use iref::Uri;
use json_ld_syntax::Context;
use serde::Serialize;
use ssi::{
    claims::{
        jws::JWSSigner,
        vc::{
            enveloped::EnvelopedVerifiableCredential,
            v2::{Credential, CredentialTypes, JsonCredential},
            MaybeIdentified,
        },
        ClaimsValidity, DateTimeProvider, JWSPayload, SignatureError, ValidateClaims,
    },
    crypto::Algorithm,
    JWK,
};
use xsd_types::DateTimeStamp;

/// Payload of a COSE-secured Verifiable Credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CoseVc<T = JsonCredential>(pub T);

impl<T: Serialize> CoseVc<T> {
    /// Sign a COSE VC into a COSE enveloped verifiable credential.
    pub async fn sign_into_cose(&self, signer: &JWK) -> Result<Vec<u8>, SignatureError> {
        let info = signer.fetch_info().await?;
        let payload_bytes = self.payload_bytes();

        let coset_alg = match signer.get_algorithm().unwrap() {
            ssi::jwk::Algorithm::EdDSA => coset::iana::Algorithm::EdDSA,
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

        Ok(sign1.to_vec().unwrap())
    }
}

fn sign_bytes(signer: &JWK, payload: &[u8]) -> Vec<u8> {
    // Copied this function out of impl JWSSigner for JWK
    // to get rid of the async-ness, which isn't compatible
    // with the coset interface.

    // TO DO: ERROR HANDLING without panic.

    let algorithm = signer.get_algorithm().unwrap();

    ssi::claims::jws::sign_bytes(algorithm, payload, signer).unwrap()
}

// NEXT STEPS: Hoist JWSSigner::sign up to here.
// Pay special attention to this line (line 88):
//
//      let signing_bytes = header.encode_signing_bytes(&payload_bytes);
//
// That calls through to ssi_jws::Header::encode_signing_bytes (line 401),
// which encodes _both_ the header and the payload (JSON encoded credential).
//
// Then line 89:
//
//      let signature = self.sign_bytes(&signing_bytes).await?;
//
// Gets the raw signature bytes over the header and payload.
// That's from impl JWSSigner for JWK::sign (line 142).
//
// And finally the call to
// CompactJWSString::encode_from_signing_bytes_and_signature base-64 encodes the
// raw signature bytes and appends it to the encoded payload and
// header to complete the JWT.

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

impl<T: Serialize> JWSPayload for CoseVc<T> {
    fn typ(&self) -> Option<&str> {
        Some("vc-ld+cose")
    }

    fn cty(&self) -> Option<&str> {
        Some("vc")
    }

    fn payload_bytes(&self) -> Cow<[u8]> {
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

/* NOT YET ...
#[cfg(test)]
mod tests {
    use serde_json::json;
    use ssi_claims_core::VerificationParameters;
    use ssi_jwk::JWK;
    use ssi_jws::{CompactJWS, CompactJWSBuf};
    use ssi_vc::v2::JsonCredential;

    use crate::CoseVc;

    async fn verify(input: &CompactJWS, key: &JWK) {
        let vc = CoseVc::decode_any(input).unwrap();
        let params = VerificationParameters::from_resolver(key);
        let result = vc.verify(params).await.unwrap();
        assert_eq!(result, Ok(()))
    }

    #[async_std::test]
    async fn jose_vc_roundtrip() {
        let vc: JsonCredential = serde_json::from_value(json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "id": "http://university.example/credentials/1872",
            "type": [
                "VerifiableCredential",
                "ExampleAlumniCredential"
            ],
            "issuer": "https://university.example/issuers/565049",
            "validFrom": "2010-01-01T19:23:24Z",
            "credentialSchema": {
                "id": "https://example.org/examples/degree.json",
                "type": "JsonSchema"
            },
            "credentialSubject": {
                "id": "did:example:123",
                "degree": {
                "type": "BachelorDegree",
                "name": "Bachelor of Science and Arts"
                }
            }
        }))
        .unwrap();

        let key = JWK::generate_p256();
        let enveloped = CoseVc(vc).sign_into_enveloped(&key).await.unwrap();
        let jws = CompactJWSBuf::new(enveloped.id.decoded_data().unwrap().into_owned()).unwrap();
        verify(&jws, &key).await
    }
}
*/
