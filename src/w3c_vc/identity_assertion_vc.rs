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

use iref::{Iri, UriBuf};
use serde::{Deserialize, Serialize};
use ssi::claims::vc::{
    syntax::{RequiredContext, RequiredType},
    v2::SpecializedJsonCredential,
};
use xsd_types::DateTimeStamp;

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
    #[serde(rename = "verifiedIdentities")]
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
    /// ## Verified identity type
    ///
    /// The `verifiedIdentities[?].type` property MUST be present and MUST be a
    /// non-empty string that defines the type of verification that was
    /// performed by the identity provider.
    ///
    /// TO DO: Find a non-empty string type.
    #[serde(rename = "type")]
    #[ld("cawg:type")]
    pub type_: String,

    /// ## Display name
    ///
    /// The `verifiedIdentities[?].name` property MAY be present. If present, it
    /// MUST NOT be empty and must be a string defining the _named actor’s_ name
    /// as understood by the identity provider.
    ///
    /// If the `type` of this verified identity is `cawg.document_verification`,
    /// the `verifiedIdentities[?].name` property MUST be present and MUST
    /// exactly match the name found on the identity documents.
    ///
    /// TO DO: Find a non-empty string type.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ld("cawg:name")]
    pub name: Option<String>,

    /// ## User name
    ///
    /// The `verifiedIdentities[?].username` property MAY be present. If
    /// present, it MUST be a non-empty text string representing the _named
    /// actor’s_ user name as assigned by the identity provider.
    ///
    /// If the type of this verified identity is `cawg.social_media`, the
    /// `verifiedIdentities[?].username` property MUST be present and MUST be
    /// the unique alphanumeric string that can be used to identity the _named
    /// actor_ within this service.
    ///
    /// TO DO: Find a non-empty string type.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ld("cawg:username")]
    pub username: Option<String>,

    /// ## Address
    ///
    /// The `verifiedIdentities[?].address` property MAY be present. If present,
    /// it MUST be a non-empty text string representing the _named actor’s_
    /// cryptographic address as assigned by the identity provider.
    ///
    /// If the type of this verified identity is `cawg.crypto_wallet`, the
    /// `verifiedIdentities[?].address` property MUST be present and MUST be the
    /// unique alphanumeric string that can be used to identity the _named
    /// actor_ within this service.
    ///
    /// TO DO: Find a non-empty string type.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ld("cawg:address")]
    pub address: Option<String>,

    /// ## URI
    ///
    /// The `verifiedIdentities[?].uri` property MAY be present. If present, it
    /// must be a valid URI which is the primary point of contact for the _named
    /// actor_ as assigned by the _identity provider._
    ///
    /// If the type of this verified identity is `cawg.social_media`, it is
    /// RECOMMENDED that the `verifiedIdentities[?].uri` be the primary web URI
    /// for the _named actor’s_ social media account.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ld("cawg:uri")]
    pub uri: Option<UriBuf>,

    /// ## Identity verification date
    ///
    /// The `verifiedIdentities[?].verifiedAt` MUST be present and MUST be a
    /// valid date-time as specified by RFC 3339. It represents the date and
    /// time when the relationship between the _named actor_ and the _identity
    /// provider_ was verified by the _identity assertion generator._
    #[serde(rename = "verifiedAt")]
    #[ld("cawg:verifiedAt")]
    pub verified_at: DateTimeStamp,

    /// ## Identity provider details
    ///
    /// The `verifiedIdentities[?].provider` property MUST be an object and MUST
    /// be present. It contains details about the _identity provider_ and the
    /// identity verification process.
    #[ld("cawg:provider")]
    pub provider: IdentityProvider,
}

/// ## Identity provider details
///
/// The `verifiedIdentities[?].provider` property MUST be an object and MUST be
/// present. It contains details about the _identity provider_ and the identity
/// verification process. This specification mentions at least three properties
/// that MAY be used to represent the _named actor’s_ verification details:
/// `id`, `name`, and `proof`.
#[derive(Debug, Deserialize, Serialize, linked_data::Serialize, linked_data::Deserialize)]
#[ld(prefix("cawg" = "https://creator-assertions.github.io/tbd/tbd/"))]
pub struct IdentityProvider {
    /// ## Identity provider ID
    ///
    /// The `verifiedIdentities[?].provider.id` MUST be present and MUST be a
    /// valid URI that, when dereferenced, MUST result in a proof of
    /// authenticity of the _identity provider._ This proof of authenticity of
    /// the identity provider MUST NOT be confused with the proof of
    /// verification of the _named actor._
    #[ld(id)]
    pub id: UriBuf,

    /// ## Identity provider name
    ///
    /// The `verifiedIdentities[?].provider.name` MUST be present and MUST be a
    /// non-empty string. ///The `verifiedIdentities[?].provider.name` property
    /// is the user-visible name of the _identity provider._
    ///
    /// TO DO: Find a non-empty string type.
    #[ld("cawg:address")]
    pub name: String,
}
