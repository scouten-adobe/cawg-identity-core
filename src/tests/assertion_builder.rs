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

use std::{fs::OpenOptions, io::Seek};

use c2pa::{
    create_signer, external_manifest::ManifestPatchCallback, Manifest, ManifestStore, SigningAlg,
    Store,
};

use crate::{
    builder::credential_holder::NaiveCredentialHolder,
    tests::fixtures::{fixture_path, temp_dir_path},
    AssertionBuilder,
};

struct IdentityManifestBuilder {}

impl ManifestPatchCallback for IdentityManifestBuilder {
    fn patch_manifest(&self, manifest_store: &[u8]) -> c2pa::Result<Vec<u8>> {
        // TEMPORARY: no-op
        Ok(manifest_store.to_owned())
    }
}

#[test]
fn simple_case() {
    // TO DO: Clean up code and extract into builder interface.
    // For now, just looking for a simple proof-of-concept.

    let signcert_path = fixture_path("certs/ps256.pub");
    let pkey_path = fixture_path("certs/ps256.pem");

    let signer =
        create_signer::from_files(signcert_path, pkey_path, SigningAlg::Ps256, None).unwrap();

    let source = fixture_path("cloud.jpg");

    let temp_dir = tempfile::tempdir().unwrap();
    let dest = temp_dir_path(&temp_dir, "cloud_output.jpg");

    let mut input_stream = OpenOptions::new().read(true).open(&source).unwrap();

    let mut output_stream = OpenOptions::new()
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

    let mut store = manifest.to_store().unwrap();

    let placed_manifest = store
        .get_placed_manifest(signer.reserve_size(), "jpg", &mut input_stream)
        .unwrap();

    let identity_post_processor = IdentityManifestBuilder {};
    let callbacks: Vec<Box<dyn ManifestPatchCallback>> = vec![Box::new(identity_post_processor)];

    input_stream.rewind().unwrap(); // likely not necessary

    Store::embed_placed_manifest(
        &placed_manifest,
        "jpg",
        &mut input_stream,
        &mut output_stream,
        signer.as_ref(),
        &callbacks,
    )
    .unwrap();

    let manifest_store = ManifestStore::from_file(&dest).unwrap();
    println!("{manifest_store}");
    assert!(manifest_store.validation_status().is_none());

    // TO DO: Validate identity assertion.
}
