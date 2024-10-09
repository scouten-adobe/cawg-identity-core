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

#![allow(unused)] // TEMPORARY while rebuilding
#![allow(dead_code)] // TEMPORARY while rebuilding

use std::{collections::HashMap, fs::OpenOptions, io::Cursor, str::FromStr};

use c2pa::{Manifest, ManifestStore, Signer};
use iref::UriBuf;
use non_empty_string::NonEmptyString;
use serde::Serialize;
use ssi::{
    claims::{
        vc::{
            syntax::{IdOr, NonEmptyVec},
            v2::Credential,
        },
        vc_jose_cose::JoseVc,
        JwsPayload,
    },
    dids::DIDJWK,
    JWK,
};
use static_iref::uri;
use xsd_types::value::DateTimeStamp;

use crate::{
    builder::{CredentialHolder, IdentityAssertionBuilder, ManifestBuilder},
    claim_aggregation::{
        temp_cose::CoseVc, IdentityAssertionVc, IdentityClaimsAggregationVc, IdentityProvider,
        VcVerifiedIdentity,
    },
    tests::fixtures::{temp_c2pa_signer, temp_dir_path},
    IdentityAssertion, SignerPayload,
};

#[tokio::test]
async fn adobe_connected_identities() {
    let manifest_store = ManifestStore::from_file(
        "src/tests/fixtures/claim_aggregation/adobe_connected_identities.jpg",
    )
    .unwrap();
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

    assert_eq!(
        report.signer_payload.sig_type,
        "cawg.identity_claims_aggregation"
    );

    dbg!(&report.named_actor);

    for vi in report.named_actor.verified_identities() {
        dbg!(vi.type_());
    }
}

fn non_empty_str(s: &str) -> NonEmptyString {
    NonEmptyString::try_from(s).unwrap()
}
