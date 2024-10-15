// Derived from
// https://github.com/spruceid/ssi/blob/ssi/v0.9.0/crates/jwk/src/lib.rs
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
#![allow(unused)]

use std::{
    convert::TryFrom, fmt, num::ParseIntError, result::Result, str::FromStr, string::FromUtf8Error,
};

use base64::{DecodeError as Base64Error, Engine};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

// use num_bigint::{BigInt, Sign};
// use simple_asn1::{ASN1Block, ASN1Class, ToASN1};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq)]
pub(crate) struct JWK {
    #[serde(rename = "use")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_use: Option<String>,
    #[serde(rename = "key_ops")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_operations: Option<Vec<String>>,
    #[serde(rename = "alg")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<Algorithm>,
    #[serde(rename = "kid")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(rename = "x5u")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x509_url: Option<String>,
    #[serde(rename = "x5c")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x509_certificate_chain: Option<Vec<String>>,
    #[serde(rename = "x5t")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x509_thumbprint_sha1: Option<Base64urlUInt>,
    #[serde(rename = "x5t#S256")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x509_thumbprint_sha256: Option<Base64urlUInt>,
    #[serde(flatten)]
    pub params: Params,
}

impl FromStr for JWK {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}

impl TryFrom<&[u8]> for JWK {
    type Error = serde_json::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(bytes)
    }
}

impl TryFrom<serde_json::Value> for JWK {
    type Error = serde_json::Error;

    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        serde_json::from_value(value)
    }
}

impl fmt::Display for JWK {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let json =
            serde_json::to_string_pretty(self).unwrap_or_else(|_| "unable to serialize".to_owned());
        f.write_str(&json)
    }
}

impl From<Params> for JWK {
    fn from(params: Params) -> Self {
        Self {
            params,
            public_key_use: None,
            key_operations: None,
            algorithm: None,
            key_id: None,
            x509_url: None,
            x509_certificate_chain: None,
            x509_thumbprint_sha1: None,
            x509_thumbprint_sha256: None,
        }
    }
}
// linked_data::json_literal!(JWK);

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq, Zeroize)]
#[serde(tag = "kty")]
pub enum Params {
    // TEMPORARY: Only supporting Ed25519 for now
    // EC(ECParams),
    // RSA(RSAParams),
    // #[serde(rename = "oct")]
    // Symmetric(SymmetricParams),
    OKP(OctetParams),
}

impl Drop for OctetParams {
    fn drop(&mut self) {
        // Zeroize private key
        if let Some(ref mut d) = self.private_key {
            d.zeroize();
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq, Zeroize)]
pub struct OctetParams {
    // Parameters for Octet Key Pair Public Keys
    #[serde(rename = "crv")]
    pub curve: String,
    #[serde(rename = "x")]
    pub public_key: Base64urlUInt,

    // Parameters for Octet Key Pair Private Keys
    #[serde(rename = "d")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<Base64urlUInt>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq, Zeroize)]
#[serde(try_from = "String")]
#[serde(into = "Base64urlUIntString")]
pub struct Base64urlUInt(pub Vec<u8>);
type Base64urlUIntString = String;

impl JWK {
    pub fn generate_ed25519() -> Result<JWK, Error> {
        let mut csprng = rand::rngs::OsRng {};
        let secret = ed25519_dalek::SigningKey::generate(&mut csprng);
        let public = secret.verifying_key();
        Ok(JWK::from(Params::OKP(OctetParams {
            curve: "Ed25519".to_string(),
            public_key: Base64urlUInt(public.as_ref().to_vec()),
            private_key: Some(Base64urlUInt(secret.to_bytes().to_vec())),
        })))
    }

    pub fn get_algorithm(&self) -> Option<Algorithm> {
        if let Some(algorithm) = self.algorithm {
            return Some(algorithm);
        }
        match &self.params {
            Params::OKP(okp_params) if okp_params.curve == "Ed25519" => {
                return Some(Algorithm::EdDsa);
            }
            _ => {}
        };
        None
    }

    // /// Strip private key material
    // // TODO: use separate type
    // pub fn to_public(&self) -> Self {
    //     let mut key = self.clone();
    //     key.params = key.params.to_public();
    //     key
    // }

    // pub fn is_public(&self) -> bool {
    //     self.params.is_public()
    // }

    // /// Compare JWK equality by public key properties.
    // /// Equivalent to comparing by [JWK Thumbprint][Self::thumbprint].
    // pub fn equals_public(&self, other: &JWK) -> bool {
    //     match (&self.params, &other.params) {
    //         (
    //             Params::RSA(RSAParams {
    //                 modulus: Some(n1),
    //                 exponent: Some(e1),
    //                 ..
    //             }),
    //             Params::RSA(RSAParams {
    //                 modulus: Some(n2),
    //                 exponent: Some(e2),
    //                 ..
    //             }),
    //         ) => n1 == n2 && e1 == e2,
    //         (Params::OKP(okp1), Params::OKP(okp2)) => {
    //             okp1.curve == okp2.curve && okp1.public_key == okp2.public_key
    //         }
    //         (
    //             Params::EC(ECParams {
    //                 curve: Some(crv1),
    //                 x_coordinate: Some(x1),
    //                 y_coordinate: Some(y1),
    //                 ..
    //             }),
    //             Params::EC(ECParams {
    //                 curve: Some(crv2),
    //                 x_coordinate: Some(x2),
    //                 y_coordinate: Some(y2),
    //                 ..
    //             }),
    //         ) => crv1 == crv2 && x1 == x2 && y1 == y2,
    //         (
    //             Params::Symmetric(SymmetricParams {
    //                 key_value: Some(kv1),
    //             }),
    //             Params::Symmetric(SymmetricParams {
    //                 key_value: Some(kv2),
    //             }),
    //         ) => kv1 == kv2,
    //         _ => false,
    //     }
    // }

    // pub fn thumbprint(&self) -> Result<String, Error> {
    //     // JWK parameters for thumbprint hashing must be in lexicographical
    // order, and without     // string escaping.
    //     // https://datatracker.ietf.org/doc/html/rfc7638#section-3.1
    //     let json_string = match &self.params {
    //         Params::RSA(rsa_params) => {
    //             let n =
    // rsa_params.modulus.as_ref().ok_or(Error::MissingModulus)?;
    // let e = rsa_params.exponent.as_ref().ok_or(Error::MissingExponent)?;
    //             format!(
    //                 r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#,
    //                 String::from(e),
    //                 String::from(n)
    //             )
    //         }
    //         Params::OKP(okp_params) => {
    //             format!(
    //                 r#"{{"crv":"{}","kty":"OKP","x":"{}"}}"#,
    //                 okp_params.curve.clone(),
    //                 String::from(okp_params.public_key.clone())
    //             )
    //         }
    //         Params::EC(ec_params) => {
    //             let curve = ec_params.curve.as_ref().ok_or(Error::MissingCurve)?;
    //             let x =
    // ec_params.x_coordinate.as_ref().ok_or(Error::MissingPoint)?;
    // let y = ec_params.y_coordinate.as_ref().ok_or(Error::MissingPoint)?;
    //             format!(
    //                 r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#,
    //                 curve.clone(),
    //                 String::from(x),
    //                 String::from(y)
    //             )
    //         }
    //         Params::Symmetric(sym_params) => {
    //             let k = sym_params
    //                 .key_value
    //                 .as_ref()
    //                 .ok_or(Error::MissingKeyValue)?;
    //             format!(r#"{{"k":"{}","kty":"oct"}}"#, String::from(k))
    //         }
    //     };
    //     let hash = ssi_crypto::hashes::sha256::sha256(json_string.as_bytes());
    //     let thumbprint = String::from(Base64urlUInt(hash.to_vec()));
    //     Ok(thumbprint)
    // }
}

/*
impl TryFrom<&OctetParams> for ed25519_dalek::VerifyingKey {
    type Error = Error;
    fn try_from(params: &OctetParams) -> Result<Self, Self::Error> {
        if params.curve != *"Ed25519" {
            return Err(Error::CurveNotImplemented(params.curve.to_string()));
        }
        Ok(params.public_key.0.as_slice().as_ref().try_into()?)
    }
}

impl TryFrom<&OctetParams> for ed25519_dalek::SigningKey {
    type Error = Error;
    fn try_from(params: &OctetParams) -> Result<Self, Self::Error> {
        if params.curve != *"Ed25519" {
            return Err(Error::CurveNotImplemented(params.curve.to_string()));
        }
        let private_key = params
            .private_key
            .as_ref()
            .ok_or(Error::MissingPrivateKey)?;
        Ok(private_key.0.as_slice().as_ref().try_into()?)
    }
}
*/

pub fn ed25519_parse(data: &[u8]) -> Result<JWK, Error> {
    let public_key = ed25519_dalek::VerifyingKey::try_from(data)?;
    Ok(public_key.into())
}

impl From<ed25519_dalek::VerifyingKey> for JWK {
    fn from(value: ed25519_dalek::VerifyingKey) -> Self {
        JWK::from(Params::OKP(OctetParams {
            curve: "Ed25519".to_string(),
            public_key: Base64urlUInt(value.to_bytes().to_vec()),
            private_key: None,
        }))
    }
}

fn ed25519_parse_private(data: &[u8]) -> Result<JWK, Error> {
    let key: ed25519_dalek::SigningKey = data.try_into()?;
    Ok(JWK::from(Params::OKP(OctetParams {
        curve: "Ed25519".to_string(),
        public_key: Base64urlUInt(ed25519_dalek::VerifyingKey::from(&key).as_bytes().to_vec()),
        private_key: Some(Base64urlUInt(data.to_owned())),
    })))
}

const BASE64_URL_SAFE_INDIFFERENT_PAD: base64::engine::GeneralPurpose =
    base64::engine::GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        base64::engine::GeneralPurposeConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    );

impl TryFrom<String> for Base64urlUInt {
    type Error = base64::DecodeError;

    fn try_from(data: String) -> Result<Self, Self::Error> {
        Ok(Base64urlUInt(BASE64_URL_SAFE_INDIFFERENT_PAD.decode(data)?))
    }
}

impl From<&Base64urlUInt> for String {
    fn from(data: &Base64urlUInt) -> String {
        base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(&data.0)
    }
}

impl From<Base64urlUInt> for Base64urlUIntString {
    fn from(data: Base64urlUInt) -> Base64urlUIntString {
        String::from(&data)
    }
}

/// Signature algorithm.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Hash, Eq)]
pub enum Algorithm {
    // TEMPORARY: Only supporting Ed25519 for now.
    #[serde(rename = "EdDSA")]
    EdDsa,

    #[serde(alias = "None")]
    None,
}

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Missing curve in JWK
    #[error("Missing curve in JWK")]
    MissingCurve,

    /// Missing elliptic curve point in JWK
    #[error("Missing elliptic curve point in JWK")]
    MissingPoint,

    /// Missing key value for symmetric key
    #[error("Missing key value for symmetric key")]
    MissingKeyValue,

    /// Key type is not supported
    #[error("Key type not supported")]
    UnsupportedKeyType,

    /// Key type not implemented
    #[error("Key type not implemented for {0}")]
    KeyTypeNotImplemented(Box<JWK>),

    /// Curve not implemented
    #[error("Curve not implemented: '{0}'")]
    CurveNotImplemented(String),

    /// Missing private key parameter in JWK
    #[error("Missing private key parameter in JWK")]
    MissingPrivateKey,

    /// Invalid key length
    #[error("Invalid key length: {0}")]
    InvalidKeyLength(usize),

    /// Error parsing a UTF-8 string
    #[error(transparent)]
    FromUtf8(#[from] FromUtf8Error),

    /// Error decoding Base64
    #[error(transparent)]
    Base64(#[from] Base64Error),

    /// Error parsing integer
    #[error(transparent)]
    ParseInt(#[from] ParseIntError),

    /// Expected 64 byte uncompressed key or 33 bytes compressed key
    #[error("Expected 64 byte uncompressed key or 33 bytes compressed key but found length: {0}")]
    P256KeyLength(usize),

    /// Expected 96 byte uncompressed key or 49 bytes compressed key (P-384)
    #[error("Expected 96 byte uncompressed key or 49 bytes compressed key but found length: {0}")]
    P384KeyLength(usize),

    /// Unable to decompress elliptic curve
    #[error("Unable to decompress elliptic curve")]
    ECDecompress,

    #[error(transparent)]
    CryptoErr(#[from] ed25519_dalek::ed25519::Error),

    /// Unexpected length for publicKeyMultibase
    #[error("Unexpected length for publicKeyMultibase")]
    MultibaseKeyLength(usize, usize),

    /// Error parsing or producing multibase
    #[error(transparent)]
    Multibase(#[from] multibase::Error),

    #[error("Invalid coordinates")]
    InvalidCoordinates,
}
