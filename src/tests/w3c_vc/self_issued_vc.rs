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

//! WARNING: did:key is great for simple test cases such as this
//! but is strongly discouraged as a production use case.

#![allow(unused)] // TEMPORARY while building
use std::fs::OpenOptions;

use async_trait::async_trait;
use c2pa::{Manifest, ManifestStore};
use did_method_key::DIDKey;
use ssi::{
    did::{DIDMethods, Source},
    jsonld::ContextLoader,
    jwk::JWK,
    vc::{
        Context, Contexts, Credential, CredentialOrJWT, LinkedDataProofOptions, OneOrMany,
        Presentation, URI,
    },
};

use crate::{
    builder::{CredentialHolder, IdentityAssertionBuilder, ManifestBuilder},
    tests::fixtures::{fixture_path, temp_c2pa_signer, temp_dir_path},
    w3c_vc::{VcNamedActor, VcSignatureHandler},
    IdentityAssertion, SignerPayload,
};

/// TO DO: Move what we can from this to more generic code in pub mod w3c_vc.

struct DidKeySelfIssuer {
    user_jwk: JWK,
    issuer_jwk: JWK,
}

impl DidKeySelfIssuer {
    pub fn new() -> Self {
        Self {
            user_jwk: JWK::generate_ed25519().unwrap(),
            issuer_jwk: JWK::generate_ed25519().unwrap(),
        }
    }

    async fn credential(&self) -> Credential {
        // TO DO: ERROR HANDLING

        let mut methods = DIDMethods::default();
        methods.insert(Box::new(DIDKey));

        let user_did = methods
            .generate(&Source::KeyAndPattern(&self.user_jwk, "key"))
            .unwrap();

        let issuer_did = methods
            .generate(&Source::KeyAndPattern(&self.issuer_jwk, "key"))
            .unwrap();

        let mut id_vc: Credential = Credential::from_json_unsigned(
            &serde_json::json!(
            {
                "@context": ["https://www.w3.org/2018/credentials/v1","https://schema.org/"],
                "id": "http://example.org/credentials/3731",
                "type": [
                  "VerifiableCredential",
                  "Person"
                ],
                "credentialSubject": {
                  "id": user_did,
                  "name": "Sample User Fred",
                },
                "issuer": issuer_did,
                "issuanceDate": "2023-11-06T21:43:29Z",

              })
            .to_string(),
        )
        .unwrap();

        id_vc.add_proof(
            id_vc
                .generate_proof(
                    &self.issuer_jwk,
                    &LinkedDataProofOptions::default(),
                    &DIDKey,
                    &mut ContextLoader::default(),
                )
                .await
                .unwrap(),
        );

        id_vc
    }

    async fn add_proof(&self, presentation: &mut Presentation, options: &LinkedDataProofOptions) {
        // TO DO: ERROR HANDLING
        presentation.add_proof(
            presentation
                .generate_proof(
                    &self.user_jwk,
                    &options,
                    &DIDKey,
                    &mut ContextLoader::default(),
                )
                .await
                .unwrap(),
        );
    }
}

#[async_trait::async_trait]
impl CredentialHolder for DidKeySelfIssuer {
    fn sig_type(&self) -> &'static str {
        "cawg.w3c.vc"
    }

    fn reserve_size(&self) -> usize {
        10240 // 🤷🏻‍♂️
    }

    async fn sign(&self, signer_payload: &SignerPayload) -> c2pa::Result<Vec<u8>> {
        // TO DO: ERROR HANDLING
        let claim_id = "TBD:need_to_replace_this";

        let actor_vc = self.credential().await;

        let OneOrMany::One(ref subject) = actor_vc.credential_subject else {
            panic!("HANDLE THIS ERROR: Credential must name exactly one subject");
        };

        let Some(ref subject) = subject.id else {
            panic!("HANDLE THIS ERROR: Credential subject must exist");
        };

        let URI::String(subject) = subject;
        // ^^ No `else` clause because URI enum has no other
        // current values.

        let subject = subject.clone();

        // TO DO: Verify that did method is on the allow list.
        // TO DO: Perform independent verification on VC now?

        let mut vp = Presentation {
            context: Contexts::One(Context::URI(URI::String(
                "https://www.w3.org/2018/credentials/v1".to_string(),
            ))),
            id: None,
            type_: OneOrMany::One("VerifiablePresentation".to_string()),
            verifiable_credential: Some(OneOrMany::One(CredentialOrJWT::Credential(actor_vc))),
            proof: None,
            holder: Some(URI::String(subject)),
            holder_binding: None,
            property_set: None,
        };

        let vp_options = LinkedDataProofOptions {
            domain: Some(claim_id.to_owned()),
            // challenge: Some(pc_hash.clone()), (do we need this?)
            ..LinkedDataProofOptions::default()
        };

        self.add_proof(&mut vp, &vp_options).await;

        eprintln!("VP is\n{}\n\n", serde_json::to_string_pretty(&vp).unwrap());

        let vp = serde_json::to_string(&vp)?;
        Ok(vp.as_bytes().to_owned())
    }
}

#[actix::test]
async fn simple_case() {
    // TO DO: Clean up code and extract into builder interface.
    // For now, just looking for a simple proof-of-concept.

    // let source = fixture_path("cloud.jpg");
    let source =
        std::path::PathBuf::from("/Users/scouten/Adobe/identity-core/src/tests/fixtures/cloud.jpg");

    let mut input_stream = OpenOptions::new().read(true).open(&source).unwrap();

    let temp_dir = tempfile::tempdir().unwrap();
    let dest = temp_dir_path(&temp_dir, "cloud_output.jpg");

    let mut output_stream = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&dest)
        .unwrap();

    // TO DO: Add a metadata assertion as an example.

    // Here we act as an identity assertion creator.

    let self_did_key = DidKeySelfIssuer::new();

    let iab = IdentityAssertionBuilder::for_credential_holder(self_did_key);

    let signer = temp_c2pa_signer();
    let mut mb = ManifestBuilder::default();
    mb.add_assertion(iab);

    let manifest: Manifest = Manifest::new("identity_test/simple_case");
    mb.build(
        manifest,
        "jpg",
        &mut input_stream,
        &mut output_stream,
        signer.as_ref(),
    )
    .await
    .unwrap();

    /*
    // Here we act as an identity assertion consumer.

    let manifest_store = ManifestStore::from_file(&dest).unwrap();
    assert!(manifest_store.validation_status().is_none());

    let manifest = manifest_store.get_active().unwrap();
    let identity: IdentityAssertion = manifest.find_assertion("cawg.identity").unwrap();

    let _sp = identity.check_signer_payload(manifest).unwrap();
    identity.check_padding().unwrap();

    let report = identity.validate(manifest).await.unwrap();

    let sp = report.signer_payload;
    let ra = &sp.referenced_assertions;
    assert_eq!(ra.len(), 1);

    let ra1 = ra.first().unwrap();
    assert_eq!(ra1.url, "self#jumbf=c2pa.assertions/c2pa.hash.data");
    assert_eq!(ra1.alg, Some("sha256".to_owned()));

    assert_eq!(report.signer_payload.sig_type, "cawg.x509.cose");

    let na = report.named_actor;
    assert_eq!(
        na.display_name(),
        Some("C2PA Test Signing Cert".to_string())
    );

    assert!(!na.is_trusted());
    */

    unimplemented!();
}
