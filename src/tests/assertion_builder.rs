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

#![allow(unused_mut)] // TEMPORARY while building
#![allow(unused_variables)] // TEMPORARY while building

use std::fs::OpenOptions;

use c2pa::{create_signer, Manifest, SigningAlg};

use crate::{
    tests::fixtures::{fixture_path, temp_dir_path},
    AssertionBuilder, NaiveCredentialHolder,
};

#[test]
fn simple_case() {
    let signcert_path = fixture_path("certs/ps256.pub");
    let pkey_path = fixture_path("certs/ps256.pem");

    let signer =
        create_signer::from_files(signcert_path, pkey_path, SigningAlg::Ps256, None).unwrap();

    let source = fixture_path("cloud.jpg");

    let temp_dir = tempfile::tempdir().unwrap();
    let dest = temp_dir_path(&temp_dir, "cloud_output.jpg");

    let mut input_file = OpenOptions::new().read(true).open(&source).unwrap();

    let mut output_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&dest)
        .unwrap();

    let mut manifest = Manifest::new("identity_test/simple_case");

    let naive_credential = NaiveCredentialHolder {};
    let mut identity_assertion = AssertionBuilder::for_credential_holder(naive_credential);

    // TO DO: Add a metadata assertion as an example.

    manifest.add_assertion(&identity_assertion).unwrap();

    // CONSULT WITH GAVIN: This is where I'll need to start writing preliminary
    // manifest and then substituting the finalized identity assertion.
}
