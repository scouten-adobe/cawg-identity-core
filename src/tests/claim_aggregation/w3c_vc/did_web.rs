// Derived from
// https://github.com/spruceid/ssi/blob/ssi/v0.9.0/crates/dids/methods/web/src/lib.rs
// which was published under an Apache 2.0 license.

// Subsequent modifications are subject to license from Adobe
// as follows:

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

use crate::claim_aggregation::w3c_vc::{did::Did, did_web};

#[tokio::test]
async fn to_url() {
    // https://w3c-ccg.github.io/did-method-web/#example-3-creating-the-did
    assert_eq!(
        did_web::to_url(did("did:web:w3c-ccg.github.io").method_specific_id()).unwrap(),
        "https://w3c-ccg.github.io/.well-known/did.json"
    );
    // https://w3c-ccg.github.io/did-method-web/#example-4-creating-the-did-with-optional-path
    assert_eq!(
        did_web::to_url(did("did:web:w3c-ccg.github.io:user:alice").method_specific_id()).unwrap(),
        "https://w3c-ccg.github.io/user/alice/did.json"
    );
    // https://w3c-ccg.github.io/did-method-web/#optional-path-considerations
    assert_eq!(
        did_web::to_url(did("did:web:example.com:u:bob").method_specific_id()).unwrap(),
        "https://example.com/u/bob/did.json"
    );
    // https://w3c-ccg.github.io/did-method-web/#example-creating-the-did-with-optional-path-and-port
    assert_eq!(
        did_web::to_url(did("did:web:example.com%3A443:u:bob").method_specific_id()).unwrap(),
        "https://example.com:443/u/bob/did.json"
    );
}

mod resolve {
    use http::header::{HeaderValue, CONTENT_TYPE};
    use hyper::{
        service::{make_service_fn, service_fn},
        Body, Response, Server,
    };
    use ssi_dids_core::{document::representation::MediaType, Document};

    use super::did;
    use crate::claim_aggregation::w3c_vc::did_web::{self, PROXY};

    #[tokio::test]
    async fn from_did_key() {
        let (url, shutdown) = web_server().unwrap();

        PROXY.with(|proxy| {
            proxy.replace(Some(url));
        });

        let doc = did_web::resolve(did("did:web:localhost")).await.unwrap();

        let doc_expected = Document::from_bytes(MediaType::JsonLd, DID_JSON.as_bytes()).unwrap();

        assert_eq!(doc.document.document(), doc_expected.document());

        PROXY.with(|proxy| {
            proxy.replace(None);
        });

        shutdown().ok();
    }

    /*
    #[tokio::test]
    async fn credential_prove_verify_did_web() {
        let didweb = VerificationMethodDIDResolver::new(DIDWeb);
        let params = VerificationParameters::from_resolver(&didweb);

        let (url, shutdown) = web_server().unwrap();
        PROXY.with(|proxy| {
            proxy.replace(Some(url));
        });

        let cred = JsonCredential::new(
            None,
            did!("did:web:localhost").to_owned().into_uri().into(),
            "2021-01-26T16:57:27Z".parse().unwrap(),
            vec![json_syntax::json!({
                "id": "did:web:localhost"
            })],
        );

        let key: JWK = include_str!("../../../../../tests/ed25519-2020-10-18.json")
            .parse()
            .unwrap();
        let verification_method = iri!("did:web:localhost#key1").to_owned().into();
        let suite = AnySuite::pick(&key, Some(&verification_method)).unwrap();
        let issue_options = ProofOptions::new(
            "2021-01-26T16:57:27Z".parse().unwrap(),
            verification_method,
            ProofPurpose::Assertion,
            Default::default(),
        );
        let signer = SingleSecretSigner::new(key).into_local();
        let vc = suite
            .sign(cred, &didweb, &signer, issue_options)
            .await
            .unwrap();

        println!(
            "proof: {}",
            serde_json::to_string_pretty(&vc.proofs).unwrap()
        );
        assert_eq!(vc.proofs.first().unwrap().signature.as_ref(), "eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..BCvVb4jz-yVaTeoP24Wz0cOtiHKXCdPcmFQD_pxgsMU6aCAj1AIu3cqHyoViU93nPmzqMLswOAqZUlMyVnmzDw");
        assert!(vc.verify(&params).await.unwrap().is_ok());

        // test that issuer property is used for verification
        let mut vc_bad_issuer = vc.clone();
        vc_bad_issuer.issuer = uri!("did:pkh:example:bad").to_owned().into();
        // It should fail.
        assert!(vc_bad_issuer.verify(params).await.unwrap().is_err());

        PROXY.with(|proxy| {
            proxy.replace(None);
        });
        shutdown().ok();
    }
    */

    const DID_URL: &str = "http://localhost/.well-known/did.json";
    const DID_JSON: &str = r#"{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:web:localhost",
  "verificationMethod": [{
     "id": "did:web:localhost#key1",
     "type": "Ed25519VerificationKey2018",
     "controller": "did:web:localhost",
     "publicKeyBase58": "2sXRz2VfrpySNEL6xmXJWQg6iY94qwNp1qrJJFBuPWmH"
  }],
  "assertionMethod": ["did:web:localhost#key1"]
}"#;

    // localhost web server for serving did:web DID documents.
    // TODO: pass arguments here instead of using const
    fn web_server() -> Result<(String, impl FnOnce() -> Result<(), ()>), hyper::Error> {
        let addr = ([127, 0, 0, 1], 0).into();

        let make_svc = make_service_fn(|_| async move {
            Ok::<_, hyper::Error>(service_fn(|req| async move {
                let uri = req.uri();

                // Skip leading slash
                let proxied_url: String = uri.path().chars().skip(1).collect();
                if proxied_url == DID_URL {
                    let body = Body::from(DID_JSON);
                    let mut response = Response::new(body);
                    response
                        .headers_mut()
                        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
                    return Ok::<_, hyper::Error>(response);
                }

                let (mut parts, body) = Response::<Body>::default().into_parts();
                parts.status = hyper::StatusCode::NOT_FOUND;

                let response = Response::from_parts(parts, body);
                Ok::<_, hyper::Error>(response)
            }))
        });

        let server = Server::try_bind(&addr)?.serve(make_svc);
        let url = "http://".to_string() + &server.local_addr().to_string() + "/";

        let (shutdown_tx, shutdown_rx) = futures::channel::oneshot::channel();

        let graceful = server.with_graceful_shutdown(async {
            shutdown_rx.await.ok();
        });

        tokio::task::spawn(async move {
            graceful.await.ok();
        });

        let shutdown = || shutdown_tx.send(());
        Ok((url, shutdown))
    }
}

fn did(s: &'static str) -> &Did {
    Did::new(s.as_bytes()).unwrap()
}
