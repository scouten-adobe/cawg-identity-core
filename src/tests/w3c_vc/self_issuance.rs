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

use super::test_issuer::TestIssuer;

#[actix::test]
async fn default_case() {
    let ti = TestIssuer::new();
    ti.test_basic_case().await;
}

#[actix::test]
#[should_panic] // TEMPORARY until error results are implemented
async fn error_no_issuer() {
    let ti = TestIssuer::from_asset_vc(
        r#"{
            "@context": "https://www.w3.org/2018/credentials/v1",
            "type": "VerifiableCredential",
            "credentialSubject": {
                "id": "did:key:z6Mkmf541wxtnV7n5YAnToRw5JRHJUMQYHBzpkCzyRTHpuL8"
            }
        }"#,
    );

    ti.test_basic_case().await;
}

#[actix::test]
#[should_panic] // TEMPORARY until error results are implemented
async fn error_no_issuance_date() {
    let ti = TestIssuer::from_asset_vc(
        r#"{
            "@context": "https://www.w3.org/2018/credentials/v1",
            "type": "VerifiableCredential",
            "credentialSubject": {
                "id": "did:key:z6Mkp4n6JaXdECTcy7GLsWrc2bUmSYi3nbKt5grWQznFdYKz"
            },
            "issuer": "did:key:z6MkmJhxUFcNhqWqapiPMWhCk6QjSnqRGdiUfmBdVw6Haf7G"
        }"#,
    );

    ti.test_basic_case().await;
}

#[actix::test]
#[should_panic] // TEMPORARY until error results are implemented
async fn error_no_proof() {
    let ti = TestIssuer::from_asset_vc(
        r#"{
            "@context": "https://www.w3.org/2018/credentials/v1",
            "type": "VerifiableCredential",
            "credentialSubject": {
                "id": "did:key:z6Mktf2a2pRkJuiwUKPcyWSNnWMwgCoUvqtjmYfYUwiqVx3u"
            },
            "issuer": "did:key:z6MkicKWYcotCaNY2aPz6rftxr9wkj8K6JzfRhQadycEApnB",
            "issuanceDate": "2024-07-18T21:20:08Z"
        }"#,
    );

    ti.test_basic_case().await;
}
