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

use serde::{Deserialize, Serialize};

use crate::c2pa::HashedUri;

/// The set of data to be signed by the [`CredentialHolder`].
#[derive(Clone, Debug, Deserialize, Eq, Serialize, PartialEq)]
pub struct Tbs {
    /// List of assertions referenced by this credential signature
    pub referenced_assertions: Vec<HashedUri>,
}
