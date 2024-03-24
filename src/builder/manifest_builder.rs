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

use c2pa::{
    external_manifest::ManifestPatchCallback, CAIRead, CAIReadWrite, Manifest, Signer, Store,
};

use super::IdentityAssertionBuilder;

/// TO DO: Docs
#[derive(Default)]
pub struct ManifestBuilder {
    identity_assertions: Vec<IdentityAssertionBuilder>,
}

impl ManifestBuilder {
    /// Adds an identity assertion to the builder.
    pub fn add_assertion(&mut self, identity_assertion: IdentityAssertionBuilder) {
        self.identity_assertions.push(identity_assertion);
    }

    /// This function wraps all the c2pa SDK calls in the (currently)
    /// correct sequence. This is likely to change as the c2pa SDK
    /// evolves.
    pub async fn build(
        self,
        manifest: Manifest,
        format: &str,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        signer: &dyn Signer,
    ) -> c2pa::Result<()> {
        // let naive_credential = NaiveCredentialHolder {};
        // let mut identity_assertion =
        // AssertionBuilder::for_credential_holder(naive_credential);

        // manifest.add_assertion(&identity_assertion)?;

        let mut store = manifest.to_store()?;

        let placed_manifest =
            store.get_placed_manifest(signer.reserve_size(), "jpg", input_stream)?;

        let callbacks: Vec<Box<dyn ManifestPatchCallback>> = vec![Box::new(self)];

        input_stream.rewind()?;

        // TO DO: Place the async signing parts here.
        // Not (yet?)
        // compatible with the callback mechanism.

        Store::embed_placed_manifest(
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
