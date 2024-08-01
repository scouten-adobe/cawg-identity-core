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

use iref::Iri;
use serde::{Deserialize, Serialize};
use ssi::claims::vc::{
    syntax::{RequiredContext, RequiredType},
    v2::SpecializedJsonCredential,
};

/// TO DO: Doc -- looks like SpecializedJsonCredential for our specific use
/// case.
pub type IdentityAssertionVc = SpecializedJsonCredential<
    CreatorIdentityAssertion,
    CreatorIdentityAssertion,
    CreatorIdentityAssertion,
>;

/// Creator identity assertion context IRI.
pub const CREATOR_IDENTITY_ASSERTION_CONTEXT_IRI: &Iri =
    static_iref::iri!("https://creator-assertions.github.io/tbd/tbd/");

/// Creator identity assertion type name.
pub const CREATOR_IDENTITY_ASSERTION_TYPE: &str = "CreatorIdentityAssertionCredential";

/// A **creator identity assertion** is a [W3C verifiable credential] that binds
/// the identity of the _named actor_ to the _C2PA asset_ in which the
/// **identity assertion** appears.
///
/// [W3C verifiable credential]: https://www.w3.org/TR/vc-data-model-2.0/
#[derive(Debug, Deserialize, Serialize, linked_data::Serialize, linked_data::Deserialize)]
#[ld(prefix("cawg" = "https://creator-assertions.github.io/tbd/tbd/"))]
pub struct CreatorIdentityAssertion {
    /// The `verifiedIdentities` property MUST be present and MUST be an array.
    /// Every item in the array MUST contain information about the _named actor_
    /// as verified by the _identity assertion generator_ or a service contacted
    /// by the _identity assertion generator._
    #[ld("cawg:verifiedIdentities")]
    pub verified_identities: Vec<VerifiedIdentity>,
}

impl RequiredContext for CreatorIdentityAssertion {
    const CONTEXT_IRI: &'static Iri = CREATOR_IDENTITY_ASSERTION_CONTEXT_IRI;
}

impl RequiredType for CreatorIdentityAssertion {
    const REQUIRED_TYPE: &'static str = CREATOR_IDENTITY_ASSERTION_TYPE;
}

/// Every item in the `verifiedIdentities` array MUST contain information about
/// the _named actor_ as verified by the _identity assertion generator_ or a
/// service contacted by the _identity assertion generator._
#[derive(Debug, Deserialize, Serialize, linked_data::Serialize, linked_data::Deserialize)]
#[ld(prefix("cawg" = "https://creator-assertions.github.io/tbd/tbd/"))]
pub struct VerifiedIdentity {
    /// The `verifiedIdentities[?].type` property MUST be present and MUST be a
    /// non-empty string that defines the type of verification that was
    /// performed by the identity provider.
    #[ld("cawg:type")]
    pub type_: String,

    /// The `verifiedIdentities[?].name` property MAY be present. If present, it
    /// MUST NOT be empty and must be a string defining the _named actor’s_ name
    /// as understood by the identity provider.
    ///
    /// If the `type` of this verified identity is `cawg.document_verification`,
    /// the `verifiedIdentities[?].name` property MUST be present and MUST
    /// exactly match the name found on the identity documents.
    #[ld("cawg:name")]
    pub name: Option<String>,
}
