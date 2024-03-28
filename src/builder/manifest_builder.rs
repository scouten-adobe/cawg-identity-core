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

#![allow(unused_variables)] // TEMPORARY while building

use c2pa::{CAIRead, CAIReadWrite, Manifest, ManifestPatchCallback, Signer};

use super::{identity_assertion_builder::IdentityAssertion, IdentityAssertionBuilder};

/// TO DO: Docs
#[derive(Default)]
pub struct ManifestBuilder {
    identity_assertions: Vec<IdentityAssertion>,
}

impl ManifestBuilder {
    /// Adds an identity assertion to the builder.
    pub fn add_assertion(&mut self, identity_assertion: IdentityAssertionBuilder) {
        self.identity_assertions
            .push(IdentityAssertion::from_builder(identity_assertion));
    }

    /// This function wraps all the C2PA SDK calls in the (currently)
    /// correct sequence. This is likely to change as the C2PA SDK
    /// evolves.
    pub async fn build(
        self,
        mut manifest: Manifest,
        format: &str,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        signer: &dyn Signer,
    ) -> c2pa::Result<()> {
        for ia in self.identity_assertions.iter() {
            manifest.add_assertion(ia)?;
        }

        let (placed_manifest, active_manifest_label) =
            manifest.get_placed_manifest(signer.reserve_size(), "jpg", input_stream)?;

        let callbacks: Vec<Box<dyn ManifestPatchCallback>> = vec![Box::new(self)];

        // TO DO: Place the async signing parts here.
        // Not (yet?)
        // compatible with the callback mechanism.

        input_stream.rewind()?;

        Manifest::embed_placed_manifest(
            &placed_manifest,
            "jpg",
            input_stream,
            output_stream,
            signer,
            &callbacks,
        )?;

        Ok(())
    }

    fn patch_manifest_imp(&self, manifest_store: &[u8]) -> Option<Vec<u8>> {
        // let mut result_ms = manifest_store.to_vec(); // we'll need this when we start
        // patching

        let ms = crate::c2pa::ManifestStore::from_slice(manifest_store)?;
        let m = ms.active_manifest()?;
        let claim = m.claim()?;
        let ast = m.assertion_store()?;

        dbg!(&claim);

        Some(manifest_store.to_vec())
        // Some(result_ms)
    }
}

impl ManifestPatchCallback for ManifestBuilder {
    fn patch_manifest(&self, manifest_store: &[u8]) -> c2pa::Result<Vec<u8>> {
        // TO DO: Rethink error handling. For now, we fail
        // with "ClaimDecoding" reason regardless of the failure mode.

        match self.patch_manifest_imp(manifest_store) {
            Some(ms_buffer) => Ok(ms_buffer),
            None => Err(c2pa::Error::ClaimDecoding),
        }
    }
}
