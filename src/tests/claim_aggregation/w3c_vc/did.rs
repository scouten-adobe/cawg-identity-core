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

mod new {
    use crate::claim_aggregation::w3c_vc::did::Did;

    #[test]
    fn valid_dids() {
        let did = Did::new(b"did:method:foo").unwrap();
        assert_eq!(did.method_name(), "method");
        assert_eq!(did.method_specific_id(), "foo");

        let did = Did::new(b"did:a:b").unwrap();
        assert_eq!(did.method_name(), "a");
        assert_eq!(did.method_specific_id(), "b");

        let did = Did::new(b"did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9").unwrap();
        assert_eq!(did.method_name(), "jwk");
        assert_eq!(did.method_specific_id(), "eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9");

        let did = Did::new(b"did:web:example.com%3A443:u:bob").unwrap();
        assert_eq!(did.method_name(), "web");
        assert_eq!(did.method_specific_id(), "example.com%3A443:u:bob");
    }

    #[test]
    fn err_invalid_did() {
        Did::new(b"http:a:b").unwrap_err();
        Did::new(b"did::b").unwrap_err();
        Did::new(b"did:a:").unwrap_err();
    }
}
