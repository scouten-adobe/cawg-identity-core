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

#![allow(unused)] // TEMPORARY while building

use std::{
    collections::{hash_map, HashMap},
    fmt::{Debug, Formatter},
    slice::Iter,
};

use async_trait::async_trait;
use coset::{
    iana::{self, CoapContentFormat},
    CborSerializable, CoseSign1, RegisteredLabel, RegisteredLabelWithPrivate,
};
use ssi::{
    claims::vc::{
        syntax::NonEmptyVec,
        v1::{Context, Credential, Presentation},
    },
    dids::{resolution, DIDResolver, DID, DIDJWK, DIDURL},
    jwk, JWK,
};

use crate::{
    identity_assertion::VerifiedIdentities,
    w3c_vc::{
        cawg_identity_context::{cawg_context_loader, CAWG_IDENTITY_CONTEXT_IRI},
        IdentityAssertionVc, VcVerifiedIdentity,
    },
    NamedActor, SignatureHandler, SignerPayload, ValidationResult, VerifiedIdentity,
};

/// An implementation of [`SignatureHandler`] that supports Creator Identity
/// Assertions (a specific grammar of W3C Verifiable Credentials) as specified
/// in [§8.1, W3C verifiable credentials] and secured by COSE as specified in
/// [§3.3.1 Securing JSON-LD Verifiable Credentials with COSE] of _Securing
/// Verifiable Credentials using JOSE and COSE._
///
/// [`SignatureHandler`]: crate::SignatureHandler
/// [§8.1, W3C verifiable credentials]: https://creator-assertions.github.io/identity/1.x-add-vc-v3/#_w3c_verifiable_credentials
/// [§3.3.1 Securing JSON-LD Verifiable Credentials with COSE]: https://w3c.github.io/vc-jose-cose/#securing-vcs-with-cose
pub struct CoseVcSignatureHandler {}

#[async_trait]
impl SignatureHandler for CoseVcSignatureHandler {
    fn can_handle_sig_type(sig_type: &str) -> bool {
        sig_type == "cawg.w3c.vc"
    }

    async fn check_signature<'a>(
        &self,
        signer_payload: &SignerPayload,
        signature: &'a [u8],
    ) -> ValidationResult<Box<dyn NamedActor<'a>>> {
        // TEMPORARY implementation. Hopefully to be replaced by more robust code in
        // `ssi` crate soon.

        // TO DO: Error handling without panic.

        // At the receiving end, deserialize the bytes back to a `CoseSign1` object.
        let sign1 = CoseSign1::from_slice(&signature).unwrap();
        dbg!(&sign1);

        // TEMPORARY: Require EdDSA algorithm.
        let ssi_alg = if let Some(ref alg) = sign1.protected.header.alg {
            match alg {
                RegisteredLabelWithPrivate::Assigned(coset::iana::Algorithm::EdDSA) => {
                    jwk::Algorithm::EdDSA
                }
                _ => {
                    panic!("TO DO: Add suport for signing alg {alg:?}");
                }
            }
        } else {
            panic!("ERROR: COSE protected headers do not contain a signing algorithm");
        };

        if let Some(ref cty) = sign1.protected.header.content_type {
            match cty {
                coset::ContentType::Text(ref cty) => {
                    if cty != "application/vc" {
                        panic!("ERROR: COSE content type is unsupported {cty:?}");
                    }
                }
                _ => {
                    panic!("ERROR: COSE content type is unsupported {cty:?}");
                }
            }
        } else {
            panic!("ERROR: COSE protected headers do not contain required content type header");
        }

        // Interpret the unprotected payload, which should be the raw VC.

        let Some(ref payload_bytes) = sign1.payload else {
            panic!("ERROR: COSE Sign1 data structure has no payload");
        };

        let asset_vc: IdentityAssertionVc = serde_json::from_slice(&payload_bytes)
            .expect("ERROR: can't decode VC as IdentityAssertionVc");

        dbg!(&asset_vc);

        // Discover public key for issuer DID and validate signature.
        // TEMPORARY version supports JWK only.

        let issuer_id = asset_vc.issuer.id();
        let issuer_id = DIDURL::new(&issuer_id.as_bytes()).unwrap();
        let (primary_did, _fragment) = issuer_id.without_fragment();
        let primary_did = primary_did.did();

        let jwk = match primary_did.method_name() {
            "jwk" => {
                let jwk = primary_did.method_specific_id();
                let jwk = multibase::Base::decode(&multibase::Base::Base64Url, jwk).unwrap();
                let jwk: JWK = serde_json::from_slice(&jwk).unwrap();
                jwk
            }
            x => {
                panic!("Unsupported DID method {x:?}");
            }
        };

        // TEMPORARY only support ED25519.
        let jwk::Params::OKP(ref okp) = jwk.params else {
            panic!("Temporarily unsupported params type");
        };
        assert_eq!(okp.curve, "Ed25519");

        // Check the signature, which needs to have the same `aad` provided, by
        // providing a closure that can do the verify operation.
        let result = sign1
            .verify_signature(b"", |sig, data| {
                ssi::claims::jws::verify_bytes(ssi_alg, data, &jwk, sig)
            })
            .unwrap();

        // Enforce [§8.1.2.4. Validity].
        //
        // [§8.1.2.4. Validity]: https://creator-assertions.github.io/identity/1.x+vc-draft/#vc-property-validFrom

        assert!(asset_vc.valid_from.is_some());
        // TO DO: Check if ssi crate enforces valid_from < now.
        // Also check if ssi enforces expiration date.

        Ok(Box::new(VcNamedActor(asset_vc)))
    }
}

/// An implementation of [`NamedActor`] that describes the subject of a Creator
/// Identity Assertion.
///
/// [`NamedActor`]: crate::NamedActor
pub struct VcNamedActor(IdentityAssertionVc);

impl<'a> NamedActor<'a> for VcNamedActor {
    fn display_name(&self) -> Option<String> {
        // TO DO: Extract this from VC
        None
    }

    fn is_trusted(&self) -> bool {
        false
        // todo!("Is this on trust list?");
    }

    fn verified_identities(&self) -> VerifiedIdentities {
        // TO DO: Can we do a safe unwrap here because first()
        // should be guaranteed to exist?
        let subject = self.0.credential_subjects.first().unwrap();
        Box::new(VcVerifiedIdentities::new(&subject.verified_identities))
    }
}

impl Debug for VcNamedActor {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        let display_name = if let Some(dn) = self.display_name() {
            dn
        } else {
            "(none)".to_owned()
        };

        f.debug_struct("VcNamedActor")
            .field("display_name", &display_name)
            .field("(credential)", &self.0)
            .finish()
    }
}

struct VcVerifiedIdentities<'a>(Iter<'a, VcVerifiedIdentity>);

impl<'a> VcVerifiedIdentities<'a> {
    fn new(verified_identities: &'a NonEmptyVec<VcVerifiedIdentity>) -> Self {
        Self(verified_identities.iter())
    }
}

impl<'a> Iterator for VcVerifiedIdentities<'a> {
    type Item = Box<&'a dyn VerifiedIdentity>;

    fn next(&mut self) -> Option<Box<&'a dyn VerifiedIdentity>> {
        if let Some(vc_vi) = self.0.next() {
            Some(Box::new(vc_vi))
        } else {
            None
        }
    }
}
