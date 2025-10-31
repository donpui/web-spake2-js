web-spake2-js
===

The SPAKE2, SPAKE2+ password-authenticated key-exchange algorithm, in Javascript.

This is updated original implementation of https://github.com/niomon/spake2-js by Samuel Tang <samueltangz613@gmail.com>

Implementation based on:
- [RFC 9382 – SPAKE2](https://www.rfc-editor.org/rfc/rfc9382)
- [RFC 9383 – SPAKE2+](https://www.rfc-editor.org/rfc/rfc9383)

### Why:
- need to work in web browser
- original code last updated +6 years

### Note: 
- A lot of code refactored with help of AI

## Original old message

This have not go through a formal cryptographic audit and should be awared in any use case.

Also this do not protect against time attacks as operations are probably not constant-time.

## Documentation:

[Usage Readme](USAGE.md)