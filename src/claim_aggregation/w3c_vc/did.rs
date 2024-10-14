// Derived from
// https://github.com/spruceid/ssi/blob/ssi/v0.9.0/crates/dids/core/src/did.rs
// which was published under an Apache 2.0 license.

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

#![allow(dead_code)]
#![allow(unused_macros)]

use std::{borrow::Borrow, fmt, ops::Deref, str::FromStr};

use iref::UriBuf;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Error raised when a conversion to a DID fails.
#[derive(Debug, Error)]
#[error("invalid DID `{0}`: {1}")]
pub struct InvalidDid<T>(pub T, pub Unexpected);

impl<T> InvalidDid<T> {
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> InvalidDid<U> {
        InvalidDid(f(self.0), self.1)
    }
}

/// DID.
///
/// This type is unsized and used to represent borrowed DIDs. Use `DidBuf` for
/// owned DIDs.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Did(str);

impl Did {
    /// Converts the input `data` to a DID.
    ///
    /// Fails if the data is not a DID according to the
    /// [DID Syntax](https://w3c.github.io/did-core/#did-syntax).
    pub fn new<B: ?Sized + AsRef<str>>(data: &B) -> Result<&Self, InvalidDid<&B>> {
        let bytes = data.as_ref();
        match Self::validate(bytes) {
            Ok(()) => Ok(unsafe {
                // SAFETY: DID is a transparent wrapper over `[u8]`,
                //         and we just checked that `data` is a DID.
                std::mem::transmute::<&str, &Self>(bytes)
            }),
            Err(e) => Err(InvalidDid(data, e)),
        }
    }

    /// Converts the input `data` to a DID without validation.
    ///
    /// # Safety
    ///
    /// The input `data` must be a DID according to the
    /// [DID Syntax](https://w3c.github.io/did-core/#did-syntax).
    pub unsafe fn new_unchecked(data: &str) -> &Self {
        unsafe {
            // SAFETY: DID is a transparent wrapper over `[u8]`,
            //         but we didn't check if it is actually a DID.
            std::mem::transmute(data)
        }
    }

    /// Returns the DID as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the DID as a byte string.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0.as_bytes()
    }

    /// Returns the offset of the `:` byte just after the method name.
    #[allow(clippy::unwrap_used)]
    fn method_name_separator_offset(&self) -> usize {
        // SAFETY: We have validated that this is a well-formed DID already.
        self.0[5..].chars().position(|c| c == ':').unwrap() + 5 // +5 and not
                                                                // +4 because
                                                                // the method
                                                                // name cannot
                                                                // be empty.
    }

    /// Returns the DID method name.
    pub fn method_name(&self) -> &str {
        &self.0[4..self.method_name_separator_offset()]
    }

    /// Returns the DID method specific identifier.
    pub fn method_specific_id(&self) -> &str {
        &self.0[self.method_name_separator_offset() + 1..]
    }

    /// Returns the DID without any fragment qualifier.
    pub fn split_fragment(&self) -> (&Self, Option<&str>) {
        // NOTE: Can replace with split_once when we move over to str.
        if let Some((primary, fragment)) = self.0.split_once(|c| c == '#') {
            // SAFETY: A known subset of an existing checked DID.
            let primary = unsafe { Self::new_unchecked(primary) };
            (primary, Some(fragment))
        } else {
            (self, None)
        }
    }

    /// Validates a DID string.
    fn validate(data: &str) -> Result<(), Unexpected> {
        let mut chars = data.chars();
        match Self::validate_from(0, &mut chars)? {
            (_, None) => Ok(()),
            (i, Some(c)) => Err(Unexpected(i, Some(c))),
        }
    }

    /// Validates a DID string.
    fn validate_from(
        mut i: usize,
        bytes: &mut std::str::Chars<'_>,
    ) -> Result<(usize, Option<char>), Unexpected> {
        enum State {
            Scheme1,         // d
            Scheme2,         // i
            Scheme3,         // d
            SchemeSeparator, // :
            MethodNameStart,
            MethodName,
            MethodSpecificIdStartOrSeparator,
            MethodSpecificIdPct1,
            MethodSpecificIdPct2,
            MethodSpecificId,
        }

        let mut state = State::Scheme1;
        fn is_method_char(b: char) -> bool {
            matches!(b, 'a'..='z') || b.is_ascii_digit()
        }

        fn is_id_char(b: char) -> bool {
            b.is_ascii_alphanumeric() || matches!(b, '.' | '-' | '_')
        }

        loop {
            match state {
                State::Scheme1 => match bytes.next() {
                    Some('d') => state = State::Scheme2,
                    c => break Err(Unexpected(i, c)),
                },
                State::Scheme2 => match bytes.next() {
                    Some('i') => state = State::Scheme3,
                    c => break Err(Unexpected(i, c)),
                },
                State::Scheme3 => match bytes.next() {
                    Some('d') => state = State::SchemeSeparator,
                    c => break Err(Unexpected(i, c)),
                },
                State::SchemeSeparator => match bytes.next() {
                    Some(':') => state = State::MethodNameStart,
                    c => break Err(Unexpected(i, c)),
                },
                State::MethodNameStart => match bytes.next() {
                    Some(c) if is_method_char(c) => state = State::MethodName,
                    c => break Err(Unexpected(i, c)),
                },
                State::MethodName => match bytes.next() {
                    Some(':') => state = State::MethodSpecificIdStartOrSeparator,
                    Some(c) if is_method_char(c) => (),
                    c => break Err(Unexpected(i, c)),
                },
                State::MethodSpecificIdStartOrSeparator => match bytes.next() {
                    Some(':') => (),
                    Some('%') => state = State::MethodSpecificIdPct1,
                    Some(c) if is_id_char(c) => state = State::MethodSpecificId,
                    c => break Err(Unexpected(i, c)),
                },
                State::MethodSpecificIdPct1 => match bytes.next() {
                    Some(c) if c.is_ascii_hexdigit() => state = State::MethodSpecificIdPct2,
                    c => break Err(Unexpected(i, c)),
                },
                State::MethodSpecificIdPct2 => match bytes.next() {
                    Some(c) if c.is_ascii_hexdigit() => state = State::MethodSpecificId,
                    c => break Err(Unexpected(i, c)),
                },
                State::MethodSpecificId => match bytes.next() {
                    Some(':') => state = State::MethodSpecificIdStartOrSeparator,
                    Some('%') => state = State::MethodSpecificIdPct1,
                    // HACK: Add support for fragments here. Will sort out later.
                    Some(c) if is_id_char(c) || c == '#' => (),
                    c => break Ok((i, c)),
                },
            }

            i += 1
        }
    }
}

impl Deref for Did {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl PartialEq<DidBuf> for Did {
    fn eq(&self, other: &DidBuf) -> bool {
        self == other.as_did()
    }
}

impl ToOwned for Did {
    type Owned = DidBuf;

    fn to_owned(&self) -> Self::Owned {
        unsafe { DidBuf::new_unchecked(self.0.to_owned()) }
    }
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

/// Owned DID.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DidBuf(String);

impl DidBuf {
    pub fn new(data: String) -> Result<Self, InvalidDid<String>> {
        match Did::validate(&data) {
            Ok(()) => Ok(Self(data)),
            Err(e) => Err(InvalidDid(data, e)),
        }
    }

    pub unsafe fn new_unchecked(data: String) -> Self {
        Self(data)
    }

    pub fn as_did(&self) -> &Did {
        unsafe {
            // SAFETY: we validated the data in `Self::new`.
            Did::new_unchecked(&self.0)
        }
    }

    pub fn into_uri(self) -> UriBuf {
        unsafe { UriBuf::new_unchecked(self.0.into_bytes()) }
    }
}

impl TryFrom<String> for DidBuf {
    type Error = InvalidDid<String>;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        DidBuf::new(value)
    }
}

impl FromStr for DidBuf {
    type Err = InvalidDid<String>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.to_owned().try_into()
    }
}

impl Deref for DidBuf {
    type Target = Did;

    fn deref(&self) -> &Self::Target {
        self.as_did()
    }
}

impl Borrow<Did> for DidBuf {
    fn borrow(&self) -> &Did {
        self.as_did()
    }
}

impl fmt::Display for DidBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

impl fmt::Debug for DidBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

impl PartialEq<str> for DidBuf {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl<'a> PartialEq<&'a str> for DidBuf {
    fn eq(&self, other: &&'a str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<Did> for DidBuf {
    fn eq(&self, other: &Did) -> bool {
        self.as_did() == other
    }
}

impl<'a> PartialEq<&'a Did> for DidBuf {
    fn eq(&self, other: &&'a Did) -> bool {
        self.as_did() == *other
    }
}

impl Serialize for DidBuf {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_str().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DidBuf {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = DidBuf;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "a DID")
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                v.try_into().map_err(|e| E::custom(e))
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_string(v.to_string())
            }
        }

        deserializer.deserialize_string(Visitor)
    }
}

#[derive(Debug, thiserror::Error)]
pub struct Unexpected(pub usize, pub Option<char>);

impl fmt::Display for Unexpected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.1 {
            Some(b) => write!(f, "unexpected byte {b} at offset {0:#04x}", self.0),
            None => write!(f, "unexpected end at offset {0:#04x}", self.0),
        }
    }
}
