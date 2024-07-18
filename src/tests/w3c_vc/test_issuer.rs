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

use std::{fs::OpenOptions, io::Cursor};

use c2pa::{Manifest, ManifestStore};
use did_method_key::DIDKey;
use ssi::{
    did::{DIDMethods, Source},
    jwk::JWK,
    vc::{Context, Contexts, Credential, CredentialSubject, OneOrMany, URI},
};

use crate::{
    builder::{CredentialHolder, IdentityAssertionBuilder, ManifestBuilder},
    tests::fixtures::{temp_c2pa_signer, temp_dir_path},
    IdentityAssertion, SignerPayload,
};

/// TO DO: Move what we can from this to more generic code in pub mod w3c_vc.

pub(super) struct TestIssuer {
    user_jwk: JWK,
    issuer_jwk: JWK,
}

#[async_trait::async_trait]
impl CredentialHolder for TestIssuer {
    fn sig_type(&self) -> &'static str {
        "cawg.w3c.vc"
    }

    fn reserve_size(&self) -> usize {
        10240 // 🤷🏻‍♂️
    }

    async fn sign(&self, _signer_payload: &SignerPayload) -> c2pa::Result<Vec<u8>> {
        // TO DO: ERROR HANDLING
        let actor_vc = self.credential().await;

        let OneOrMany::One(ref subject) = actor_vc.credential_subject else {
            panic!("HANDLE THIS ERROR: Credential must name exactly one subject");
        };

        let Some(ref subject) = subject.id else {
            panic!("HANDLE THIS ERROR: Credential subject must exist");
        };

        let asset_vc = Credential {
            context: Contexts::One(Context::URI(URI::String(
                "https://www.w3.org/2018/credentials/v1".to_string(),
            ))),
            id: None,
            type_: OneOrMany::One("VerifiableCredential".to_string()),
            issuer: None,
            credential_subject: OneOrMany::One(CredentialSubject {
                id: Some(subject.to_owned()),
                property_set: None,
            }),
            proof: None,
            expiration_date: None,
            credential_status: None,
            property_set: None,
            issuance_date: None,
            terms_of_use: None,
            evidence: None,
            credential_schema: None,
            refresh_service: None,
        };

        eprintln!(
            "Asset VC is\n{}\n\n",
            serde_json::to_string_pretty(&asset_vc).unwrap()
        );

        let asset_vc = serde_json::to_string(&asset_vc)?;
        Ok(asset_vc.as_bytes().to_owned())
    }
}

impl TestIssuer {
    pub(super) fn new() -> Self {
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

        let id_vc: Credential = Credential::from_json_unsigned(
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

        // id_vc.add_proof(
        //     id_vc
        //         .generate_proof(
        //             &self.issuer_jwk,
        //             &LinkedDataProofOptions::default(),
        //             &DIDKey,
        //             &mut ContextLoader::default(),
        //         )
        //         .await
        //         .unwrap(),
        // );

        id_vc
    }

    // async fn add_proof(&self, presentation: &mut Presentation, options:
    // &LinkedDataProofOptions) {     // TO DO: ERROR HANDLING
    //     presentation.add_proof(
    //         presentation
    //             .generate_proof(
    //                 &self.user_jwk,
    //                 &options,
    //                 &DIDKey,
    //                 &mut ContextLoader::default(),
    //             )
    //             .await
    //             .unwrap(),
    //     );
    // }

    pub(super) async fn test_basic_case(self) {
        // TO DO: See if we can make this a non-consuming function.
        // Currently does so because IdentityAssertionBuilder takes
        // ownership of the CredentialHolder instance.

        // TO DO: Clean up code and extract into builder interface.
        // For now, just looking for a simple proof-of-concept.

        let cloud_jpg = include_bytes!("../fixtures/cloud.jpg");
        let mut input_stream = Cursor::new(cloud_jpg);

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

        let iab = IdentityAssertionBuilder::for_credential_holder(self);

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

        assert_eq!(report.signer_payload.sig_type, "cawg.w3c.vc");

        dbg!(&report.named_actor);

        unimplemented!();
    }
}
