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

use std::collections::HashMap;

use iref::Iri;
use ssi::json_ld::ContextLoader;

pub(crate) const CAWG_IDENTITY_CONTEXT_IRI: &Iri =
    static_iref::iri!("https://creator-assertions.github.io/tbd/tbd");

pub(crate) const CAWG_IDENTITY_CONTEXT_JSON: &str = r#"{
    "@context": {
        "id": "@id",
        "type": "@type"
    }
}"#;

pub(crate) fn cawg_context_loader() -> ContextLoader {
    let context_map: HashMap<String, String> = HashMap::from([(
        CAWG_IDENTITY_CONTEXT_IRI.to_string(),
        CAWG_IDENTITY_CONTEXT_JSON.to_owned(),
    )]);

    // TO DO (#27): Remove unwrap.
    #[allow(clippy::unwrap_used)]
    ssi_json_ld::ContextLoader::empty()
        .with_static_loader()
        .with_context_map_from(context_map)
        .unwrap()
}
