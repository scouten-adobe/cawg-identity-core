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

use c2pa::Manifest;

use crate::{AssertionBuilder, NaiveCredentialHolder};

#[test]
fn simple_case() {
    let mut manifest = Manifest::new("claim_generator");

    let naive_credential = NaiveCredentialHolder {};
    let mut identity_assertion = AssertionBuilder::for_credential_holder(naive_credential);

    manifest.add_assertion(&identity_assertion).unwrap();
}
