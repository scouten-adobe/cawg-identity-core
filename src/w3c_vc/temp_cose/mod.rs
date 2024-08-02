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

//! Hopefully temporary implementation of COSE enveloped signatures
//! for W3C verifiable credentials.
//!
//! Based on reading [§3.3 With COSE] of [Securing Verifiable Credentials using
//! JOSE and COSE], candidate recommendation draft as of 05 July 2024.
//!
//! Quick-and-dirty adaptation from [`ssi` crate], which I hope will add its own
//! COSE support to replace this.
//!
//!
//! [§3.3 With COSE]: https://www.w3.org/TR/vc-jose-cose/#securing-with-cose
//! [Securing Verifiable Credentials using JOSE and COSE]: https://www.w3.org/TR/vc-jose-cose/
//! [`ssi` crate]: https://github.com/spruceid/ssi/

#![allow(unused)] // TEMPORARY while building

mod credential;
pub(crate) use credential::CoseVc;
