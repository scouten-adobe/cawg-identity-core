// Loosely derived from
// https://github.com/spruceid/ssi/blob/ssi/v0.9.0/crates/dids/core/src/document.rs
// and
// https://github.com/spruceid/ssi/blob/ssi/v0.9.0/crates/dids/core/src/document/verification_method.rs
// which were published under an Apache 2.0 license.

// Subsequent modifications are subject to license from Adobe
// as follows:

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

#![allow(dead_code)] // TEMPORARY while refactoring
#![allow(unused)] // TEMPORARY while refactoring

use std::{collections::BTreeMap, str::FromStr};

use iref::IriBuf;
use serde::{Deserialize, Serialize};
use ssi_core::one_or_many::OneOrMany;

// use ssi_verification_methods_core::{ProofPurpose, ProofPurposes};
// use ssi_verification_methods_core::GenericVerificationMethod;

// use super::{
//     resource::{ExtractResource, FindResource, Resource, UsesResource},
//     ResourceRef,
// };
use super::did::{Did, DidBuf};

// pub mod representation;
// pub mod resource;
// pub mod service;

// pub use representation::Represented;
// pub use resource::{Resource, ResourceRef};
// pub use service::Service;

// use self::resource::{ExtractResource, FindResource};

/// A [DID document]
///
/// [DID document]: https://www.w3.org/TR/did-core/#dfn-did-documents
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DidDocument {
    /// DID subject identifier.
    ///
    /// See: <https://www.w3.org/TR/did-core/#did-subject>
    pub id: DidBuf,

    /// Verification relationships.
    ///
    /// Properties that express the relationship between the DID subject and a
    /// verification method using a verification relationship.
    ///
    /// See: <https://www.w3.org/TR/did-core/#verification-relationships>
    #[serde(flatten)]
    pub verification_relationships: VerificationRelationships,

    /// [`verificationMethod`](https://www.w3.org/TR/did-core/#dfn-verificationmethod) property of a
    /// DID document, expressing [verification
    /// methods](https://www.w3.org/TR/did-core/#verification-methods).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verification_method: Vec<DidVerificationMethod>,

    /// Additional properties of a DID document. Some may be registered in [DID
    /// Specification Registries](https://www.w3.org/TR/did-spec-registries/#did-document-properties).
    #[serde(flatten)]
    pub property_set: BTreeMap<String, serde_json::Value>,
}

impl DidDocument {
    /// Construct a new DID document with the given id (DID).
    pub fn new(id: DidBuf) -> DidDocument {
        DidDocument {
            id,
            verification_relationships: VerificationRelationships::default(),
            verification_method: Vec::new(),
            property_set: BTreeMap::new(),
        }
    }

    /// Construct a DID document from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /*
    /// Select an object in the DID document.
    ///
    /// See: <https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm-secondary>
    pub fn find_resource(&self, id: &DIDURL) -> Option<ResourceRef> {
        if self.id == *id {
            Some(ResourceRef::DidDocument(self))
        } else {
            self.verification_method
                .find_resource(&self.id, id)
                .or_else(|| self.verification_relationships.find_resource(&self.id, id))
        }
    }

    /// Select an object in the DID document.
    ///
    /// See: <https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm-secondary>
    pub fn into_resource(self, id: &DIDURL) -> Option<Resource> {
        if self.id == *id {
            Some(Resource::DidDocument(self))
        } else {
            self.verification_method
                .extract_resource(&self.id, id)
                .or_else(|| {
                    self.verification_relationships
                        .extract_resource(&self.id, id)
                })
        }
    }
    */
}

#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VerificationRelationships {
    /// [`authentication`](https://www.w3.org/TR/did-core/#dfn-authentication) property of a DID
    /// document, expressing [verification
    /// methods](https://www.w3.org/TR/did-core/#verification-methods) for
    /// [authentication](https://www.w3.org/TR/did-core/#authentication) purposes (e.g. generating verifiable presentations).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authentication: Vec<ValueOrReference>,

    /// [`assertionMethod`](https://www.w3.org/TR/did-core/#dfn-assertionmethod) property of a DID document, expressing [verification
    /// methods](https://www.w3.org/TR/did-core/#verification-methods) for
    /// [assertion](https://www.w3.org/TR/did-core/#assertion) purposes (e.g. issuing verifiable credentials).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assertion_method: Vec<ValueOrReference>,

    /// [`keyAgreement`](https://www.w3.org/TR/did-core/#dfn-keyagreement) property of a DID document, expressing [verification
    /// methods](https://www.w3.org/TR/did-core/#verification-methods) for
    /// [key agreement](https://www.w3.org/TR/did-core/#key-agreement) purposes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_agreement: Vec<ValueOrReference>,

    /// [`capabilityInvocation`](https://www.w3.org/TR/did-core/#dfn-capabilityinvocation) property of a DID document, expressing [verification
    /// methods](https://www.w3.org/TR/did-core/#verification-methods) for
    /// [invoking cryptographic capabilities](https://www.w3.org/TR/did-core/#capability-invocation).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_invocation: Vec<ValueOrReference>,

    /// [`capabilityDelegation`](https://www.w3.org/TR/did-core/#dfn-capabilitydelegation) property of a DID document, expressing [verification
    /// methods](https://www.w3.org/TR/did-core/#verification-methods) for
    /// [delegating cryptographic capabilities](https://www.w3.org/TR/did-core/#capability-delegation).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_delegation: Vec<ValueOrReference>,
}

/*
impl VerificationRelationships {
    pub fn proof_purpose(&self, purpose: ProofPurpose) -> &[ValueOrReference] {
        match purpose {
            ProofPurpose::Authentication => &self.authentication,
            ProofPurpose::Assertion => &self.assertion_method,
            ProofPurpose::KeyAgreement => &self.key_agreement,
            ProofPurpose::CapabilityInvocation => &self.capability_invocation,
            ProofPurpose::CapabilityDelegation => &self.capability_delegation,
        }
    }

    pub fn contains(&self, base_did: &DID, id: &DIDURL, proof_purposes: ProofPurposes) -> bool {
        for p in proof_purposes {
            for v in self.proof_purpose(p) {
                if *v.id().resolve(base_did) == *id {
                    return true;
                }
            }
        }

        false
    }
}

impl FindResource for VerificationRelationships {
    fn find_resource(&self, base_did: &DID, id: &DIDURL) -> Option<ResourceRef> {
        self.authentication
            .find_resource(base_did, id)
            .or_else(|| self.assertion_method.find_resource(base_did, id))
            .or_else(|| self.key_agreement.find_resource(base_did, id))
            .or_else(|| self.capability_invocation.find_resource(base_did, id))
            .or_else(|| self.capability_delegation.find_resource(base_did, id))
    }
}

impl ExtractResource for VerificationRelationships {
    fn extract_resource(self, base_did: &DID, id: &DIDURL) -> Option<Resource> {
        self.authentication
            .extract_resource(base_did, id)
            .or_else(|| self.assertion_method.extract_resource(base_did, id))
            .or_else(|| self.key_agreement.extract_resource(base_did, id))
            .or_else(|| self.capability_invocation.extract_resource(base_did, id))
            .or_else(|| self.capability_delegation.extract_resource(base_did, id))
    }
}
*/

/// Reference to, or value of, a verification method.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum ValueOrReference {
    Reference(DidBuf),
    Value(DidVerificationMethod),
}

/*
impl ValueOrReference {
    pub fn id(&self) -> DIDURLReference {
        match self {
            Self::Reference(r) => r.as_did_reference(),
            Self::Value(v) => DIDURLReference::Absolute(&v.id),
        }
    }

    pub fn as_value(&self) -> Option<&DidVerificationMethod> {
        match self {
            Self::Value(v) => Some(v),
            _ => None,
        }
    }
}

impl From<DIDURLBuf> for ValueOrReference {
    fn from(value: DIDURLBuf) -> Self {
        Self::Reference(value.into())
    }
}

impl From<DIDURLReferenceBuf> for ValueOrReference {
    fn from(value: DIDURLReferenceBuf) -> Self {
        Self::Reference(value)
    }
}
*/

impl From<DidVerificationMethod> for ValueOrReference {
    fn from(value: DidVerificationMethod) -> Self {
        Self::Value(value)
    }
}

/*
impl UsesResource for ValueOrReference {
    fn uses_resource(&self, base_id: &DID, id: &DIDURL) -> bool {
        match self {
            Self::Reference(r) => *r.resolve(base_id) == *id,
            Self::Value(v) => v.uses_resource(base_id, id),
        }
    }
}

impl FindResource for ValueOrReference {
    fn find_resource(&self, base_did: &DID, id: &DIDURL) -> Option<ResourceRef> {
        match self {
            Self::Reference(_) => None,
            Self::Value(m) => m.find_resource(base_did, id),
        }
    }
}

impl ExtractResource for ValueOrReference {
    fn extract_resource(self, base_did: &DID, id: &DIDURL) -> Option<Resource> {
        match self {
            Self::Reference(_) => None,
            Self::Value(m) => m.extract_resource(base_did, id),
        }
    }
}
*/

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct DidVerificationMethod {
    /// Verification method identifier.
    pub id: DidBuf,

    /// type [property](https://www.w3.org/TR/did-core/#dfn-did-urls) of a verification method map.
    /// Should be registered in [DID Specification
    /// registries - Verification method types](https://www.w3.org/TR/did-spec-registries/#verification-method-types).
    #[serde(rename = "type")]
    pub type_: String,

    // Note: different than when the DID Document is the subject:
    //    The value of the controller property, which identifies the
    //    controller of the corresponding private key, MUST be a valid DID.
    /// [controller](https://w3c-ccg.github.io/ld-proofs/#controller) property of a verification
    /// method map.
    ///
    /// Not to be confused with the [controller](https://www.w3.org/TR/did-core/#dfn-controller) property of a DID document.
    pub controller: DidBuf,

    /// Verification methods properties.
    #[serde(flatten)]
    pub properties: BTreeMap<String, serde_json::Value>,
}

impl DidVerificationMethod {
    pub fn new(
        id: DidBuf,
        type_: String,
        controller: DidBuf,
        properties: BTreeMap<String, serde_json::Value>,
    ) -> Self {
        Self {
            id,
            type_,
            controller,
            properties,
        }
    }
}

/*
impl From<DidVerificationMethod> for GenericVerificationMethod {
    fn from(value: DidVerificationMethod) -> Self {
        GenericVerificationMethod {
            id: value.id.into(),
            type_: value.type_,
            controller: value.controller.into(),
            properties: value.properties,
        }
    }
}

impl UsesResource for DidVerificationMethod {
    fn uses_resource(&self, _base_did: &DID, id: &DIDURL) -> bool {
        self.id == *id
    }
}

impl FindResource for DidVerificationMethod {
    fn find_resource(&self, _base_did: &DID, id: &DIDURL) -> Option<ResourceRef> {
        if self.id == *id {
            Some(ResourceRef::VerificationMethod(self))
        } else {
            None
        }
    }
}

impl ExtractResource for DidVerificationMethod {
    fn extract_resource(self, _base_did: &DID, id: &DIDURL) -> Option<Resource> {
        if self.id == *id {
            Some(Resource::VerificationMethod(self))
        } else {
            None
        }
    }
}
*/
