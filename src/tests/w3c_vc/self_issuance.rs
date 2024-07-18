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

//! WARNING: did:key is great for simple test cases such as this
//! but is strongly discouraged as a production use case.

use super::test_issuer::TestIssuer;

#[actix::test]
async fn default_case() {
    let ti = TestIssuer::new();
    ti.test_basic_case().await;
}
