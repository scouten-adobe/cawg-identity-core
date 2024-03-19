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

use std::{
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
};

use c2pa::{
    assertions::DataHash, create_signer, jumbf_io::get_assetio_handler_from_path, CAIReadWrite,
    HashRange, Manifest, ManifestStore, Signer, SigningAlg,
};
use tempfile::TempDir;

use crate::tests::fixtures::fixture_path;

#[test]
fn test_data_hash_embeddable_manifest() {
    let ap = fixture_path("cloud.jpg");

    let signer = temp_signer();

    let mut manifest = Manifest::new("claim_generator");

    // get a placeholder the manifest
    let placeholder = manifest
        .data_hash_placeholder(signer.reserve_size(), "tiff")
        .unwrap();

    let temp_dir = tempfile::tempdir().unwrap();
    let output = temp_dir_path(&temp_dir, "boxhash-out.jpg");
    let mut output_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&output)
        .unwrap();

    // write a jpeg file with a placeholder for the manifest (returns offset of the
    // placeholder)
    let offset = write_jpeg_placeholder_file(&placeholder, &ap, &mut output_file).unwrap();

    // build manifest to insert in the hole

    // create an hash exclusion for the manifest
    let exclusion = HashRange::new(offset, placeholder.len());
    let exclusions = vec![exclusion];

    let mut dh = DataHash::new("source_hash", "sha256");
    dh.exclusions = Some(exclusions);

    // TO DO: Update with new version of data_hash_embeddable_manifest that
    // creates the hard binding assertion but doesn't sign.

    let signed_manifest = manifest
        .data_hash_embeddable_manifest(&dh, signer.as_ref(), "image/jpeg", Some(&mut output_file))
        .unwrap();

    use std::io::{Seek, SeekFrom, Write};

    // path in new composed manifest
    output_file.seek(SeekFrom::Start(offset as u64)).unwrap();
    output_file.write_all(&signed_manifest).unwrap();

    let manifest_store = ManifestStore::from_file(&output).expect("from_file");
    println!("{manifest_store}");
    assert!(manifest_store.validation_status().is_none());
}

fn temp_signer() -> Box<dyn Signer> {
    let sign_cert = include_bytes!("./fixtures/certs/ps256.pub").to_vec();
    let pem_key = include_bytes!("./fixtures/certs/ps256.pem").to_vec();

    create_signer::from_keys(&sign_cert, &pem_key, SigningAlg::Ps256, None)
        .expect("get_temp_signer")
}

fn temp_dir_path(temp_dir: &TempDir, file_name: &str) -> PathBuf {
    let mut path = PathBuf::from(temp_dir.path());
    path.push(file_name);
    path
}

pub fn write_jpeg_placeholder_file(
    placeholder: &[u8],
    input: &Path,
    output_file: &mut dyn CAIReadWrite,
) -> c2pa::Result<usize> {
    // get where we will put the data
    let mut f = std::fs::File::open(input).unwrap();
    let jpeg_io = get_assetio_handler_from_path(input).unwrap();
    let box_mapper = jpeg_io.asset_box_hash_ref().unwrap();
    let boxes = box_mapper.get_box_map(&mut f).unwrap();
    let sof = boxes.iter().find(|b| b.names[0] == "SOF0").unwrap();

    // build new asset with hole for new manifest
    let outbuf = Vec::new();
    let mut out_stream = Cursor::new(outbuf);
    let mut input_file = std::fs::File::open(input).unwrap();

    // write before
    let mut before = vec![0u8; sof.range_start];
    input_file.read_exact(before.as_mut_slice()).unwrap();
    // if let Some(hasher) = hasher.as_deref_mut() {
    //     hasher.update(&before);
    // }
    out_stream.write_all(&before).unwrap();

    // write placeholder
    out_stream.write_all(placeholder).unwrap();

    // write bytes after
    let mut after_buf = Vec::new();
    input_file.read_to_end(&mut after_buf).unwrap();
    // if let Some(hasher) = hasher {
    //     hasher.update(&after_buf);
    // }
    out_stream.write_all(&after_buf).unwrap();

    // save to output file
    output_file.write_all(&out_stream.into_inner()).unwrap();

    Ok(sof.range_start)
}
