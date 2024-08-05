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

#![allow(unused)] // TEMPORARY while building

use std::{
    collections::{hash_map, HashMap},
    fmt::{Debug, Formatter},
};

use async_trait::async_trait;
use coset::{
    iana::{self, CoapContentFormat},
    CborSerializable, CoseSign1, RegisteredLabel, RegisteredLabelWithPrivate,
};
use ssi::claims::vc::v1::{Context, Credential, Presentation};

use crate::{
    w3c_vc::{
        cawg_identity_context::{cawg_context_loader, CAWG_IDENTITY_CONTEXT_URI},
        IdentityAssertionVc,
    },
    NamedActor, SignatureHandler, SignerPayload, ValidationResult,
};

/// An implementation of [`SignatureHandler`] that supports Creator Identity
/// Assertions (a specific grammar of W3C Verifiable Credentials) as specified
/// in [§8.1, W3C verifiable credentials] and secured by COSE as specified in
/// [§3.3.1 Securing JSON-LD Verifiable Credentials with COSE] of _Securing
/// Verifiable Credentials using JOSE and COSE._
///
/// [`SignatureHandler`]: crate::SignatureHandler
/// [§8.1, W3C verifiable credentials]: https://creator-assertions.github.io/identity/1.x-add-vc-v3/#_w3c_verifiable_credentials
/// [§3.3.1 Securing JSON-LD Verifiable Credentials with COSE]: https://w3c.github.io/vc-jose-cose/#securing-vcs-with-cose
pub struct CoseVcSignatureHandler {}

#[async_trait]
impl SignatureHandler for CoseVcSignatureHandler {
    fn can_handle_sig_type(sig_type: &str) -> bool {
        sig_type == "cawg.w3c.vc"
    }

    async fn check_signature<'a>(
        &self,
        signer_payload: &SignerPayload,
        signature: &'a [u8],
    ) -> ValidationResult<Box<dyn NamedActor<'a>>> {
        // TEMPORARY implementation. Hopefully to be replaced by more robust code in
        // `ssi` crate soon.

        // TO DO: Error handling without panic.

        // At the receiving end, deserialize the bytes back to a `CoseSign1` object.
        let sign1 = CoseSign1::from_slice(&signature).unwrap();
        dbg!(&sign1);

        // TEMPORARY: Require EdDSA algorithm.
        if let Some(alg) = sign1.protected.header.alg {
            match alg {
                RegisteredLabelWithPrivate::Assigned(coset::iana::Algorithm::EdDSA) => (),
                _ => {
                    panic!("TO DO: Add suport for signing alg {alg:?}");
                }
            }
        } else {
            panic!("ERROR: COSE protected headers do not contain a signing algorithm");
        }

        // TO DO: Discover public key for issuer DID.
        // TO DO: Validate signature against public key.
        // // Check the signature, which needs to have the same `aad` provided, by
        // // providing a closure that can do the verify operation.
        // let result = sign1.verify_signature(aad, |sig, data| verifier.verify(sig,
        // data)); println!("Signature verified: {:?}.", result);
        // assert!(result.is_ok());

        if let Some(cty) = sign1.protected.header.content_type {
            match cty {
                coset::ContentType::Text(ref cty) => {
                    if cty != "application/vc" {
                        panic!("ERROR: COSE content type is unsupported {cty:?}");
                    }
                }
                _ => {
                    panic!("ERROR: COSE content type is unsupported {cty:?}");
                }
            }
        } else {
            panic!("ERROR: COSE protected headers do not contain required content type header");
        }

        // Interpret the unprotected payload, which should be the raw VC.

        let Some(payload_bytes) = sign1.payload else {
            panic!("ERROR: COSE Sign1 data structure has no payload");
        };

        let asset_vc: IdentityAssertionVc = serde_json::from_slice(&payload_bytes)
            .expect("ERROR: can't decode VC as IdentityAssertionVc");

        dbg!(&asset_vc);

        unimplemented!("Now what?");

        /*

        --- REBUILD with SSI 0.8.0

        let mut options = LinkedDataProofOptions::default();
        options.proof_purpose = Some(ssi_dids::VerificationRelationship::AssertionMethod);

        // TO DO: Support other DID methods.
        let key_resolver = did_method_key::DIDKey {};
        let mut loader = cawg_context_loader();
        let result = vc.verify(Some(options), &key_resolver, &mut loader).await;

        assert!(result.checks.len() == 1);
        assert!(result.warnings.is_empty());
        assert!(result.errors.is_empty());

        dbg!(&result);

        // Check VC context requirements.

        // TEMPORARY: Skip this for now because ssi crate isn't ready
        // for VC V2.
        // assert!(vc
        //     .context
        //     .contains_uri("https://www.w3.org/ns/credentials/v2"));

        assert!(vc.context.contains_uri(CAWG_IDENTITY_CONTEXT_URI));

        // Check VC type requirements.

        assert!(vc.type_.contains(&"VerifiableCredential".to_owned()));
        assert!(vc.type_.contains(&"CreatorIdentityAssertion".to_owned()));

        */

        /* ---- From older identity prototype ----
        // NOTE vp is: &Presentation


        // Ensure that the proof and VC holder are properly bound.
        let Some(ref actor_vc) = vp.verifiable_credential else {
            panic!("HANDLE THIS ERROR: No VC in the VP.")
        };

        let OneOrMany::One(actor_vc) = actor_vc else {
            panic!("HANDLE THIS ERROR: VC has multiple credentials.");
        };

        let CredentialOrJWT::Credential(actor_vc) = actor_vc else {
            panic!("HANDLE THIS ERROR: VC is actually a JWT.");
        };

        let OneOrMany::One(ref subject) = actor_vc.credential_subject else {
            panic!("HANDLE THIS ERROR: Multiple credential subjects.");
        };

        let Some(ref subject) = subject.id else {
            panic!("HANDLE THIS ERROR: subject.id missing.");
        };

        let URI::String(subject) = subject;
        // ^^ No `else` clause because URI enum has no other
        // current values.

        // Make sure the presentation correctly identifies the partial claim.
        let Some(ref proof) = vp.proof else {
            panic!("HANDLE THIS ERROR: VP doesn't contain a proof.");
        };

        let OneOrMany::One(proof) = proof else {
            panic!("HANDLE THIS ERROR: VP contains multiple proofs.");
        };

        let Some(ref verification_method) = proof.verification_method else {
            panic!("HANDLE THIS ERROR: VP doens't contain a verification method");
        };

        // Ignore multibaseValue for this comparison.
        // TO DO: Is this specific to `did:key`?
        let verification_method = match verification_method.split_once('#') {
            Some((vm, _)) => vm,
            _ => verification_method,
        };

        let Some(ref domain) = proof.domain else {
            panic!("HANDLE THIS ERROR: VP doesn't contain a domain");
        };

        if verification_method != subject {
            panic!("HANDLE THIS ERROR: Proof doesn't match credential holder");
        }

        let partial_claim_id = id_for_partial_claim(partial_claim);
        if domain != &partial_claim_id {
            panic!("HANDLE THIS ERROR: Proof doesn't match partial claim ID");
        }

        Ok(())
        */

        /* ---- From CAWG X.509 branch ----
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

        Ok(Box::new(VcNamedActor(verified)))
        */
    }
}

/// An implementation of [`NamedActor`] that describes the subject of a Creator
/// Identity Assertion.
///
/// [`NamedActor`]: crate::NamedActor
pub struct VcNamedActor();

impl<'a> NamedActor<'a> for VcNamedActor {
    fn display_name(&self) -> Option<String> {
        // TO DO: Extract this from VC
        None
    }

    fn is_trusted(&self) -> bool {
        false
        // todo!("Is this on trust list?");
    }
}

impl Debug for VcNamedActor {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        let display_name = if let Some(dn) = self.display_name() {
            dn
        } else {
            "(none)".to_owned()
        };

        f.debug_struct("VcNamedActor")
            .field("display_name", &display_name)
            .finish()
    }
}
