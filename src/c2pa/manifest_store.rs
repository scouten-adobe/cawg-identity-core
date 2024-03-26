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

use std::fmt::{Debug, Formatter};

use hex_literal::hex;
use jumbf::parser::{ChildBox, SuperBox};

use crate::debug_byte_slice::DebugByteSlice;

const LABEL: &str = "c2pa";
const UUID: &[u8; 16] = &hex!("6332706100110010800000aa00389b71");

/// C2PA data is serialized into a JUMBF-compatible box structure. The outermost
/// box is referred to as the C2PA Manifest Store, also known as the Content
/// Credentials.
///
/// Definition from [C2PA Technical Specification :: Manifest Store].
///
/// [C2PA Technical Specification :: Manifest Store]: https://c2pa.org/specifications/specifications/2.0/specs/C2PA_Specification.html#_manifest_store
pub struct ManifestStore<'a> {
    /// Parsed manifest boxes
    sbox: SuperBox<'a>,

    /// Raw JUMBF data
    jumbf: &'a [u8],
}

impl<'a> ManifestStore<'a> {
    /// Parse the top level of the JUMBF box into a manifest store.
    ///
    /// Does not recurse into individual manifests. That is done on-demand
    /// when requested.
    ///
    /// Returns `None` if unable to parse as a manifest store.
    pub fn from_slice(jumbf: &'a [u8]) -> Option<Self> {
        let (_, sbox) = SuperBox::from_slice_with_depth_limit(jumbf, 0).ok()?;

        if sbox.desc.label != Some(LABEL) {
            return None;
        }

        if sbox.desc.uuid != UUID {
            return None;
        }

        Some(Self { sbox, jumbf })
    }

    /// Returns the active manifest in this manifest store.
    ///
    /// The last _[C2PA Manifest]_ superbox in the _[C2PA Manifest Store]_
    /// superbox is the _active manifest._
    ///
    /// Definition from [C2PA Technical Specification :: Locating the Active
    /// Manifest].
    ///
    /// [C2PA Manifest]: crate::c2pa::Manifest
    /// [C2PA Manifest Store]: crate::c2pa::ManifestStore
    ///
    /// [C2PA Technical Specification :: Locating the Active Manifest]: https://c2pa.org/specifications/specifications/2.0/specs/C2PA_Specification.html#_locating_the_active_manifest
    ///
    /// Returns `None` if no valid manifests are found.
    pub fn active_manifest(&'a self) -> Option<&'a ChildBox<'a>> {
        // TO DO: Change to Manifest once we have that type defined.
        self.sbox.child_boxes.last()
    }
}
