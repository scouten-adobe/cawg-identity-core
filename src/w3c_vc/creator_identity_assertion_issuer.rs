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
//! for verifiable credential as specified in [§8.1, W3C verifiable
//! credentials].
//!
//! [`CredentialHolder`]: crate::builder::CredentialHolder
//! [`SignatureHandler`]: crate::SignatureHandler
//! [§8.1, W3C verifiable credentials]: https://creator-assertions.github.io/identity/1.x-add-vc-v3/#_w3c_verifiable_credentials

#![allow(unused)] // TEMPORARY while building

use std::fmt::{Debug, Formatter};

use async_trait::async_trait;
use c2pa::SigningAlg;
use ssi::{
    did::DIDMethods,
    vc::{
        Context, Contexts, Credential, CredentialOrJWT, LinkedDataProofOptions, OneOrMany,
        Presentation, URI,
    },
};

use crate::{
    builder::CredentialHolder, NamedActor, SignatureHandler, SignerPayload, ValidationError,
    ValidationResult,
};

/// An implementation of [`CredentialHolder`] that supports varying forms of
/// credentials and generates W3C verifiable credential as the identity
/// assertion signature as specified in [§8.1, W3C verifiable credentials].
///
/// [`CredentialHolder`]: crate::builder::CredentialHolder
/// [§8.1, W3C verifiable credentials]: https://creator-assertions.github.io/identity/1.x-add-vc-v3/#_w3c_verifiable_credentials
pub struct CredentialIdentityAssertionIssuer {}

impl CredentialIdentityAssertionIssuer {
    /// TO DO: Docs
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait::async_trait]
impl CredentialHolder for CredentialIdentityAssertionIssuer {
    fn sig_type(&self) -> &'static str {
        "cawg.x509.cose"
    }

    fn reserve_size(&self) -> usize {
        10240 // 🤷🏻‍♂️
    }

    async fn sign(&self, signer_payload: &SignerPayload) -> c2pa::Result<Vec<u8>> {
        // // VC holder's countersignature references the SHA-256
        // // hash of the partial claim.
        // let claim_id = id_for_partial_claim(partial_claim);

        // let actor_vc = vc_holder.credential().await?;

        // let OneOrMany::One(ref subject) = actor_vc.credential_subject else {
        //     panic!("HANDLE THIS ERROR: Credential must name exactly one subject");
        // };

        // let Some(ref subject) = subject.id else {
        //     panic!("HANDLE THIS ERROR: Credential subject must exist");
        // };

        // let URI::String(subject) = subject;
        // // ^^ No `else` clause because URI enum has no other
        // // current values.

        // let subject = subject.clone();

        // // TO DO: Verify that did method is on the allow list.
        // // TO DO: Perform independent verification on VC now?

        // let mut vp = Presentation {
        //     context: Contexts::One(Context::URI(URI::String(
        //         "https://www.w3.org/2018/credentials/v1".to_string(),
        //     ))),
        //     id: None,
        //     type_: OneOrMany::One("VerifiablePresentation".to_string()),
        //     verifiable_credential:
        // Some(OneOrMany::One(CredentialOrJWT::Credential(actor_vc))),
        //     proof: None,
        //     holder: Some(URI::String(subject)),
        //     holder_binding: None,
        //     property_set: None,
        // };

        // let vp_options = LinkedDataProofOptions {
        //     domain: Some(claim_id.clone()),
        //     // challenge: Some(pc_hash.clone()), (do we need this?)
        //     ..LinkedDataProofOptions::default()
        // };

        // vc_holder.add_proof(&mut vp, &vp_options).await?;

        // let vp = serde_json::to_string(&vp)?;
        // let vp = vp.as_bytes().to_owned();

        // Ok((CountersignatureType::VerifiablePresentation, vp))

        unimplemented!();
    }
}
