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

use std::fmt::{Debug, Formatter};

use async_trait::async_trait;

use crate::{NamedActor, SignatureHandler, SignerPayload, ValidationResult};

/// An implementation of [`SignatureHandler`] that supports Creator Identity
/// Assertions (a specific grammar of W3C Verifiable Credentials) as specified
/// in [§8.1, W3C verifiable credentials].
///
/// [`SignatureHandler`]: crate::SignatureHandler
/// [§8.1, W3C verifiable credentials]: https://creator-assertions.github.io/identity/1.x-add-vc-v3/#_w3c_verifiable_credentials
pub struct VcSignatureHandler {}

#[async_trait]
impl SignatureHandler for VcSignatureHandler {
    fn can_handle_sig_type(sig_type: &str) -> bool {
        sig_type == "cawg.w3c.vc"
    }

    async fn check_signature<'a>(
        &self,
        signer_payload: &SignerPayload,
        signature: &'a [u8],
    ) -> ValidationResult<Box<dyn NamedActor<'a>>> {
        /* ---- From older identity prototype ----
        // NOTE vp is: &Presentation

        // use ssi::{
        //     did::DIDMethods,
        //     vc::{
        //         Context, Contexts, Credential, CredentialOrJWT, LinkedDataProofOptions, OneOrMany,
        //         Presentation, URI,
        //     },
        // };

        vp.validate().unwrap();

        let partial_claim_id = id_for_partial_claim(partial_claim);

        let mut options = LinkedDataProofOptions::default();
        options.proof_purpose = Some(ssi_dids::VerificationRelationship::AssertionMethod);

        // TO DO: Support other DID methods.
        let key_resolver = did_method_key::DIDKey {};
        let mut loader = ssi_json_ld::ContextLoader::empty().with_static_loader();

        let result = vp.verify(Some(options), &key_resolver, &mut loader).await;
        assert!(result.checks.len() == 1);
        assert!(result.warnings.is_empty());
        assert!(result.errors.is_empty());

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

        unimplemented!();
    }
}

/// An implementation of [`NamedActor`] that describes the subject of a Creator
/// Identity Assertion.
///
/// [`NamedActor`]: crate::NamedActor
pub struct VcNamedActor();

impl<'a> NamedActor<'a> for VcNamedActor {
    fn display_name(&self) -> Option<String> {
        unimplemented!();
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
