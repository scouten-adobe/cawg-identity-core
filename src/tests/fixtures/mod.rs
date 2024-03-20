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

use std::{env, path::PathBuf};

#[allow(dead_code)]
pub(crate) fn fixture_path(name: &str) -> PathBuf {
    let root_dir = &env::var("CARGO_MANIFEST_DIR").unwrap();

    let mut path = PathBuf::from(root_dir);
    path.push("src/tests/fixtures");
    path.push(name);

    assert!(path.exists());

    path
}
