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
    external_manifest::ManifestPatchCallback, AsyncSigner, CAIRead, CAIReadWrite, Manifest, Store,
};

/// TO DO: Docs
pub struct ManifestBuilder {}

impl ManifestBuilder {
    /// This function wraps all the c2pa SDK calls in the (currently)
    /// correct sequence. This is likely to change as the c2pa SDK
    /// evolves.
    pub async fn build(
        manifest: Manifest,
        format: &str,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        signer: &dyn AsyncSigner,
    ) -> c2pa::Result<()> {
        // let naive_credential = NaiveCredentialHolder {};
        // let mut identity_assertion =
        // AssertionBuilder::for_credential_holder(naive_credential);

        // manifest.add_assertion(&identity_assertion)?;

        let mut store = manifest.to_store()?;

        let placed_manifest =
            store.get_placed_manifest(signer.reserve_size(), "jpg", input_stream)?;

        let identity_post_processor = ManifestBuilder {};
        let callbacks: Vec<Box<dyn ManifestPatchCallback>> =
            vec![Box::new(identity_post_processor)];

        input_stream.rewind()?;

        Store::embed_placed_manifest_async(
            &placed_manifest,
            "jpg",
            input_stream,
            output_stream,
            signer,
            &callbacks,
        )
        .await?;

        Ok(())
    }
}

impl ManifestPatchCallback for ManifestBuilder {
    fn patch_manifest(&self, manifest_store: &[u8]) -> c2pa::Result<Vec<u8>> {
        // TEMPORARY: no-op
        Ok(manifest_store.to_owned())
    }
}
