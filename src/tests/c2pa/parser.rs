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

use std::fs;

use crate::{c2pa::ManifestStore, tests::fixtures::*};

#[test]
fn basic_case() {
    // Quick proof that we can parse the C2PA JUMBF structure.
    let jumbf: Vec<u8> = fs::read(fixture_path("C.c2pa")).unwrap();

    let ms = ManifestStore::from_slice(&jumbf).unwrap();
    let _m = ms.active_manifest().unwrap();
}

#[test]
fn error_wrong_manifest_store_box_type() {
    let mut jumbf = fs::read(fixture_path("C.c2pa")).unwrap();
    jumbf[17] = b'3'; // box type = 'c3pa'

    assert!(ManifestStore::from_slice(&jumbf).is_none());
}

#[test]
fn error_wrong_manifest_store_label() {
    let mut jumbf = fs::read(fixture_path("C.c2pa")).unwrap();
    jumbf[36] = b'b'; // label = 'c2pb'

    assert!(ManifestStore::from_slice(&jumbf).is_none());
}

#[test]
fn error_wrong_manifest_box_uuid() {
    let mut jumbf = fs::read(fixture_path("C.c2pa")).unwrap();
    jumbf[64] = 1; // wrong UUID

    let ms = ManifestStore::from_slice(&jumbf).unwrap();
    assert!(ms.active_manifest().is_none());
}
