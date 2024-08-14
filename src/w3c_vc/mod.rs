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

//! Contains implementations of [`CredentialHolder`] and [`SignatureHandler`]
//! for the W3C verifiable credential type described as specified in [§8.1, W3C
//! verifiable credential].
//!
//! [`CredentialHolder`]: crate::builder::CredentialHolder
//! [`SignatureHandler`]: crate::SignatureHandler
//! [§8.1, W3C verifiable credentials]: https://creator-assertions.github.io/identity/1.x-add-vc-v3+schema/#_w3c_verifiable_credentials

mod cose_vc_signature_handler;
pub use cose_vc_signature_handler::{CoseVcSignatureHandler, VcNamedActor};

mod identity_assertion_vc;
pub use identity_assertion_vc::{
    CreatorIdentityAssertion, IdentityAssertionVc, IdentityProvider, VcVerifiedIdentity,
};

pub(crate) mod temp_cose;
