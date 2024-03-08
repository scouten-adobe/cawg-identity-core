# Implementation of CAWG identity assertion core specification

EXPERIMENTAL/EARLY implementation of the core of the [Creator Assertions Working Group identity assertion draft specification](https://creator-assertions.github.io/identity/).

## Contributions and feedback

We welcome contributions to this project. For information on contributing, providing feedback, and about ongoing work, see [Contributing](./CONTRIBUTING.md).

## Requirements

The toolkit requires **Rust version 1.74.0** or newer. When a newer version of Rust becomes required, a new minor (1.x.0) version of this crate will be released.

### Supported platforms

The toolkit has been tested on the following operating systems:

* Windows
  * Only the MSVC build chain is supported on Windows. We would welcome a PR to enable GNU build chain support on Windows.

* MacOS (Intel and Apple silicon)

* Ubuntu Linux on x86 and ARM v8 (aarch64)

## License

The `cawg-identity-core` crate is distributed under the terms of both the MIT license and the Apache License (Version 2.0).

See [LICENSE-APACHE](./LICENSE-APACHE) and [LICENSE-MIT](./LICENSE-MIT).

Note that some components and dependent crates are licensed under different terms; please check the license terms for each crate and component for details.
