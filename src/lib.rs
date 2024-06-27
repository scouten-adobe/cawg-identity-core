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

#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(missing_docs)]
#![deny(warnings)]
#![doc = include_str!("../README.md")]

pub mod builder;

mod identity_assertion;
pub use identity_assertion::{
    HashedUri, IdentityAssertion, IdentityAssertionReport, NamedActor, SignatureHandler,
    SignerPayload, ValidationError, ValidationResult,
};

pub(crate) mod internal;

#[cfg(test)]
pub(crate) mod tests;

pub mod x509;

// Hopefully temporary hack while we sort out OpenSSL thread-safety
// issues in c2pa-rs.
use std::sync::Mutex;
#[allow(dead_code)] // Only used in test code.
static TEMP_OPENSSL_MUTEX: Mutex<()> = Mutex::new(());
