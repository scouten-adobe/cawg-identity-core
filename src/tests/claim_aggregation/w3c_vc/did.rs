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

use crate::claim_aggregation::w3c_vc::did::*;

#[test]
fn parse_did_accept() {
    let vectors: [&[u8]; 4] = [
            b"did:method:foo",
            b"did:a:b",
            b"did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9",
            b"did:web:example.com%3A443:u:bob"
        ];

    for input in vectors {
        Did::new(input).unwrap();
    }
}

#[test]
fn parse_did_reject() {
    let vectors: [&[u8]; 3] = [b"http:a:b", b"did::b", b"did:a:"];

    for input in vectors {
        assert!(Did::new(input).is_err())
    }
}
