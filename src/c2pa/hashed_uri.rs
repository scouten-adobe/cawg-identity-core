// Copyright 2022 Adobe. All rights reserved.
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

use std::fmt::{Debug, Formatter};

use serde::{Deserialize, Serialize};

use crate::debug_byte_slice::DebugByteSlice;

/// A `HashedUri` provides a reference to content available within the same
/// manifest store.
///
/// This is described in §8.3, “[URI References],” of the C2PA Technical
/// Specification.
///
/// [URI References]: https://c2pa.org/specifications/specifications/2.0/specs/C2PA_Specification.html#_uri_references
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct HashedUri {
    /// JUMBF URI reference
    pub url: String,

    /// A string identifying the cryptographic hash algorithm used to compute
    /// the hash
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,

    /// Byte string containing the hash value
    #[serde(with = "serde_bytes")]
    pub hash: Vec<u8>,
}

impl Debug for HashedUri {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_struct("HashedUri")
            .field("url", &self.url)
            .field("alg", &self.alg)
            .field("hash", &DebugByteSlice(&self.hash))
            .finish()
    }
}
