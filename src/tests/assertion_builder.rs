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

use std::{
    fs::{File, OpenOptions},
    io::{Cursor, Read, Write},
    path::Path,
};

use c2pa::{
    create_signer, jumbf_io::get_assetio_handler_from_path, CAIReadWrite, Manifest, SigningAlg,
};

use crate::{
    tests::fixtures::{fixture_path, temp_dir_path},
    AssertionBuilder, NaiveCredentialHolder,
};

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

    let placeholder = manifest
        .data_hash_placeholder(signer.reserve_size(), "jpeg")
        .unwrap();

    // Write a new JPEG file with a placeholder for the manifest.
    // If successful, write_jpeg_placeholder_file returns offset of the placeholder.
    let offset = write_jpeg_placeholder_file(&placeholder, &source, &mut output_file).unwrap();

    // --- START FROM HERE ---
    // // build manifest to insert in the hole

    // // create an hash exclusion for the manifest
    // let exclusion = HashRange::new(offset, placeholder.len());
    // let exclusions = vec![exclusion];

    // let mut dh = DataHash::new("source_hash", "sha256");
    // dh.exclusions = Some(exclusions);

    // let signed_manifest = manifest
    //     .data_hash_embeddable_manifest(
    //         &dh,
    //         signer.as_ref(),
    //         "image/jpeg",
    //         Some(&mut output_file),
    //     )
    //     .unwrap();

    // use std::io::{Seek, SeekFrom, Write};

    // // path in new composed manifest
    // output_file.seek(SeekFrom::Start(offset as u64)).unwrap();
    // output_file.write_all(&signed_manifest).unwrap();

    // let manifest_store =
    // crate::ManifestStore::from_file(&output).expect("from_file");
    // println!("{manifest_store}");
    // assert!(manifest_store.validation_status().is_none());
}

// TO DO: Move this into identity builder code?
fn write_jpeg_placeholder_file(
    placeholder: &[u8],
    input: &Path,
    output_file: &mut dyn CAIReadWrite,
    // mut hasher: Option<&mut Hasher>,
) -> c2pa::Result<usize> {
    // TO DO: Clean up error handling here.
    // Q&D adaptation from c2pa-rs test code.

    // Where we will put the data?
    let mut f = File::open(input).unwrap();
    let jpeg_io = get_assetio_handler_from_path(input).unwrap();
    let box_mapper = jpeg_io.asset_box_hash_ref().unwrap();
    let boxes = box_mapper.get_box_map(&mut f).unwrap();
    let sof = boxes.iter().find(|b| b.names[0] == "SOF0").unwrap();

    // Build new asset with hole for new manifest.
    let outbuf = Vec::new();
    let mut out_stream = Cursor::new(outbuf);
    let mut input_file = std::fs::File::open(input).unwrap();

    // Write content before placeholder.
    let mut before = vec![0u8; sof.range_start];
    input_file.read_exact(before.as_mut_slice()).unwrap();
    // TO DO: Do we need hasher? It's not available in c2pa public interface.
    // For now, act as though we were passed `None` here.
    // if let Some(hasher) = hasher.as_deref_mut() {
    //     hasher.update(&before);
    // }
    out_stream.write_all(&before).unwrap();

    // Write placeholder.
    out_stream.write_all(placeholder).unwrap();

    // Write content after placeholder.
    let mut after_buf = Vec::new();
    input_file.read_to_end(&mut after_buf).unwrap();
    // TO DO: Do we need hasher? It's not available in c2pa public interface.
    // For now, act as though we were passed `None` here.
    // if let Some(hasher) = hasher {
    //     hasher.update(&after_buf);
    // }

    out_stream.write_all(&after_buf).unwrap();

    // Save to output file.
    output_file.write_all(&out_stream.into_inner()).unwrap();

    Ok(sof.range_start)
}
