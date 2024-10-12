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

#![allow(dead_code)]
// This code should only used from unit tests.
// Silence warnings about unused code when not building tests.

use std::{env, path::PathBuf};

use c2pa::{create_signer, Signer, SigningAlg};
use tempfile::TempDir;

mod naive_credential_holder;
pub(crate) use naive_credential_holder::{NaiveCredentialHolder, NaiveSignatureHandler};

pub(crate) fn fixture_path(name: &str) -> PathBuf {
    let root_dir = &env::var("CARGO_MANIFEST_DIR").unwrap();

    let mut path = PathBuf::from(root_dir);
    path.push("src/tests/fixtures");
    path.push(name);

    assert!(path.exists());

    path
}

pub(crate) fn temp_dir_path(temp_dir: &TempDir, file_name: &str) -> PathBuf {
    let mut path = PathBuf::from(temp_dir.path());
    path.push(file_name);
    path
}

pub(crate) fn temp_c2pa_signer() -> Box<dyn Signer> {
    let sign_cert = include_bytes!("../../tests/fixtures/certs/ps256.pub").to_vec();
    let pem_key = include_bytes!("../../tests/fixtures/certs/ps256.pem").to_vec();

    create_signer::from_keys(&sign_cert, &pem_key, SigningAlg::Ps256, None).unwrap()
}
