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

use super::{identity_assertion_builder::PlaceholderAssertion, IdentityAssertionBuilder};

/// TO DO: Docs
#[derive(Default)]
pub struct ManifestBuilder {
    identity_assertions: Vec<PlaceholderAssertion>,
}

impl ManifestBuilder {
    /// Adds an identity assertion to the builder.
    pub fn add_assertion(&mut self, identity_assertion: IdentityAssertionBuilder) {
        self.identity_assertions
            .push(PlaceholderAssertion::from_builder(identity_assertion));
    }

    /// This function wraps all the c2pa SDK calls in the (currently)
    /// correct sequence. This is likely to change as the c2pa SDK
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
}

impl ManifestPatchCallback for ManifestBuilder {
    fn patch_manifest(&self, manifest_store: &[u8]) -> c2pa::Result<Vec<u8>> {
        // TEMPORARY: no-op
        Ok(manifest_store.to_owned())
    }
}
