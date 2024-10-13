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

use iref::{Iri, IriBuf, Uri, UriBuf};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// mod url;

// pub use url::*;

/// Error raised when a conversion to a DID fails.
#[derive(Debug, Error)]
#[error("invalid DID `{0}`: {1}")]
pub struct InvalidDid<T>(pub T, pub Unexpected);

impl<T> InvalidDid<T> {
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> InvalidDid<U> {
        InvalidDid(f(self.0), self.1)
    }
}

macro_rules! did {
    ($did:literal) => {
        $crate::claim_aggregation::w3c_vc::did::Did::new($did).unwrap()
    };
}

/// DID.
///
/// This type is unsized and used to represent borrowed DIDs. Use `DidBuf` for
/// owned DIDs.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Did([u8]);

impl Did {
    /// Converts the input `data` to a DID.
    ///
    /// Fails if the data is not a DID according to the
    /// [DID Syntax](https://w3c.github.io/did-core/#did-syntax).
    pub fn new<B: ?Sized + AsRef<[u8]>>(data: &B) -> Result<&Self, InvalidDid<&B>> {
        let bytes = data.as_ref();
        match Self::validate(bytes) {
            Ok(()) => Ok(unsafe {
                // SAFETY: DID is a transparent wrapper over `[u8]`,
                //         and we just checked that `data` is a DID.
                std::mem::transmute::<&[u8], &Self>(bytes)
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
    pub unsafe fn new_unchecked(data: &[u8]) -> &Self {
        unsafe {
            // SAFETY: DID is a transparent wrapper over `[u8]`,
            //         but we didn't check if it is actually a DID.
            std::mem::transmute(data)
        }
    }

    pub fn as_iri(&self) -> &Iri {
        unsafe {
            // SAFETY: a DID is an IRI.
            Iri::new_unchecked(self.as_str())
        }
    }

    pub fn as_uri(&self) -> &Uri {
        unsafe {
            // SAFETY: a DID is an URI.
            Uri::new_unchecked(&self.0)
        }
    }

    /// Returns the DID as a string.
    pub fn as_str(&self) -> &str {
        unsafe {
            // SAFETY: a DID is a valid ASCII string.
            std::str::from_utf8_unchecked(&self.0)
        }
    }

    /// Returns the DID as a byte string.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the offset of the `:` byte just after the method name.
    fn method_name_separator_offset(&self) -> usize {
        self.0[5..].iter().position(|b| *b == b':').unwrap() + 5 // +5 and not
                                                                 // +4 because
                                                                 // the method
                                                                 // name cannot
                                                                 // be empty.
    }

    /// Returns the bytes of the DID method name.
    pub fn method_name_bytes(&self) -> &[u8] {
        &self.0[4..self.method_name_separator_offset()]
    }

    /// Returns the DID method name.
    pub fn method_name(&self) -> &str {
        unsafe {
            // SAFETY: the method name is a valid ASCII string.
            std::str::from_utf8_unchecked(self.method_name_bytes())
        }
    }

    /// Returns the bytes of the DID method specific identifier.
    pub fn method_specific_id_bytes(&self) -> &[u8] {
        &self.0[self.method_name_separator_offset() + 1..]
    }

    /// Returns the DID method specific identifier.
    pub fn method_specific_id(&self) -> &str {
        unsafe {
            // SAFETY: the method specific id is a valid ASCII string.
            std::str::from_utf8_unchecked(self.method_specific_id_bytes())
        }
    }

    /// Validates a DID string.
    fn validate(data: &[u8]) -> Result<(), Unexpected> {
        let mut bytes = data.iter().copied();
        match Self::validate_from(0, &mut bytes)? {
            (_, None) => Ok(()),
            (i, Some(c)) => Err(Unexpected(i, Some(c))),
        }
    }

    /// Validates a DID string.
    fn validate_from(
        mut i: usize,
        bytes: &mut impl Iterator<Item = u8>,
    ) -> Result<(usize, Option<u8>), Unexpected> {
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
        fn is_method_char(b: u8) -> bool {
            matches!(b, 0x61..=0x7a) || b.is_ascii_digit()
        }

        fn is_id_char(b: u8) -> bool {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')
        }

        loop {
            match state {
                State::Scheme1 => match bytes.next() {
                    Some(b'd') => state = State::Scheme2,
                    c => break Err(Unexpected(i, c)),
                },
                State::Scheme2 => match bytes.next() {
                    Some(b'i') => state = State::Scheme3,
                    c => break Err(Unexpected(i, c)),
                },
                State::Scheme3 => match bytes.next() {
                    Some(b'd') => state = State::SchemeSeparator,
                    c => break Err(Unexpected(i, c)),
                },
                State::SchemeSeparator => match bytes.next() {
                    Some(b':') => state = State::MethodNameStart,
                    c => break Err(Unexpected(i, c)),
                },
                State::MethodNameStart => match bytes.next() {
                    Some(c) if is_method_char(c) => state = State::MethodName,
                    c => break Err(Unexpected(i, c)),
                },
                State::MethodName => match bytes.next() {
                    Some(b':') => state = State::MethodSpecificIdStartOrSeparator,
                    Some(c) if is_method_char(c) => (),
                    c => break Err(Unexpected(i, c)),
                },
                State::MethodSpecificIdStartOrSeparator => match bytes.next() {
                    Some(b':') => (),
                    Some(b'%') => state = State::MethodSpecificIdPct1,
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
                    Some(b':') => state = State::MethodSpecificIdStartOrSeparator,
                    Some(b'%') => state = State::MethodSpecificIdPct1,
                    Some(c) if is_id_char(c) => (),
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

impl Borrow<Uri> for Did {
    fn borrow(&self) -> &Uri {
        self.as_uri()
    }
}

impl Borrow<Iri> for Did {
    fn borrow(&self) -> &Iri {
        self.as_iri()
    }
}

impl PartialEq<DidBuf> for Did {
    fn eq(&self, other: &DidBuf) -> bool {
        self == other.as_did()
    }
}

// impl PartialEq<DIDURL> for Did {
//     fn eq(&self, other: &DIDURL) -> bool {
//         other == self
//     }
// }

// impl PartialEq<DIDURLBuf> for Did {
//     fn eq(&self, other: &DIDURLBuf) -> bool {
//         other == self
//     }
// }

impl ToOwned for Did {
    type Owned = DidBuf;

    fn to_owned(&self) -> Self::Owned {
        unsafe { DidBuf::new_unchecked(self.as_bytes().to_vec()) }
    }
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

/// Owned DID.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DidBuf(Vec<u8>);

impl DidBuf {
    pub fn new(data: Vec<u8>) -> Result<Self, InvalidDid<Vec<u8>>> {
        match Did::validate(&data) {
            Ok(()) => Ok(Self(data)),
            Err(e) => Err(InvalidDid(data, e)),
        }
    }

    pub fn from_string(data: String) -> Result<Self, InvalidDid<String>> {
        Self::new(data.into_bytes()).map_err(|InvalidDid(bytes, e)| {
            InvalidDid(unsafe { String::from_utf8_unchecked(bytes) }, e)
        })
    }

    /// Creates a new DID buffer without validation.
    ///
    /// # Safety
    ///
    /// The input data must be a valid DID.
    pub unsafe fn new_unchecked(data: Vec<u8>) -> Self {
        Self(data)
    }

    pub fn as_did(&self) -> &Did {
        unsafe {
            // SAFETY: we validated the data in `Self::new`.
            Did::new_unchecked(&self.0)
        }
    }

    // pub fn as_did_url(&self) -> &DIDURL {
    //     unsafe {
    //         // SAFETY: we validated the data in `Self::new`.
    //         DIDURL::new_unchecked(&self.0)
    //     }
    // }

    pub fn into_iri(self) -> IriBuf {
        unsafe { IriBuf::new_unchecked(String::from_utf8_unchecked(self.0)) }
    }

    pub fn into_uri(self) -> UriBuf {
        unsafe { UriBuf::new_unchecked(self.0) }
    }

    pub fn into_string(self) -> String {
        unsafe { String::from_utf8_unchecked(self.0) }
    }
}

impl TryFrom<String> for DidBuf {
    type Error = InvalidDid<String>;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        DidBuf::new(value.into_bytes()).map_err(|e| {
            e.map(|bytes| unsafe {
                // SAFETY: `bytes` comes from the `value` string, which is UTF-8
                //         encoded by definition.
                String::from_utf8_unchecked(bytes)
            })
        })
    }
}

impl FromStr for DidBuf {
    type Err = InvalidDid<String>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.to_owned().try_into()
    }
}

// impl From<DidBuf> for UriBuf {
//     fn from(value: DidBuf) -> Self {
//         value.into_uri()
//     }
// }

// impl From<DidBuf> for IriBuf {
//     fn from(value: DidBuf) -> Self {
//         value.into_iri()
//     }
// }

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

// impl Borrow<DIDURL> for DidBuf {
//     fn borrow(&self) -> &DIDURL {
//         self.as_did_url()
//     }
// }

// impl Borrow<Uri> for DidBuf {
//     fn borrow(&self) -> &Uri {
//         self.as_uri()
//     }
// }

impl Borrow<Iri> for DidBuf {
    fn borrow(&self) -> &Iri {
        self.as_iri()
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

// impl PartialEq<DIDURL> for DidBuf {
//     fn eq(&self, other: &DIDURL) -> bool {
//         self.as_did() == other
//     }
// }

// impl<'a> PartialEq<&'a DIDURL> for DidBuf {
//     fn eq(&self, other: &&'a DIDURL) -> bool {
//         self.as_did() == *other
//     }
// }

// impl PartialEq<DIDURLBuf> for DidBuf {
//     fn eq(&self, other: &DIDURLBuf) -> bool {
//         self.as_did() == other
//     }
// }

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
pub struct Unexpected(pub usize, pub Option<u8>);

impl fmt::Display for Unexpected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.1 {
            Some(b) => write!(f, "unexpected byte {b} at offset {0:#04x}", self.0),
            None => write!(f, "unexpected end at offset {0:#04x}", self.0),
        }
    }
}
