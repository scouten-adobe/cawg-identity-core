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

use super::Manifest;

const LABEL: &str = "c2pa";
const UUID: &[u8; 16] = &hex!("6332706100110010800000aa00389b71");

/// On-demand parser for a C2PA Manifest Store. Parses the top-level JUMBF data
/// structure and will parse lower layers only as needed.
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
    /// The last C2PA Manifest superbox in the C2PA Manifest Store
    /// superbox is the active manifest.
    ///
    /// Returns `None` if no valid manifests are found.
    pub fn active_manifest(&'a self) -> Option<Manifest<'a>> {
        self.sbox
            .child_boxes
            .last()
            .and_then(|cb| {
                if let ChildBox::DataBox(db) = cb {
                    Some(db)
                } else {
                    None
                }
            })
            .and_then(Manifest::from_data_box)
    }
}
