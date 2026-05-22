# jose – JSON Object Signing and Encryption (header-only, C++20)

A lightweight, header-only implementation of the JOSE family of standards,
backed by [Botan](https://github.com/randombit/botan) for cryptography and
[jsoncons](https://github.com/danielaparker/jsoncons) for JSON.

---

## Modules

### `jws/` – JSON Web Signature (RFC 7515)

Low-level signing and verification of arbitrary payloads in compact serialization.
JWT is conceptually a JWS whose payload happens to be a JSON claims set.

```cpp
#include <jose/jws/jws_botan_jsoncons.hpp>

std::error_code ec;

// Sign any bytes with any jwt::algorithm::*
std::string token = jws::create()
    .set_payload("arbitrary bytes – not necessarily JSON")
    .set_type("JOSE")
    .set_key_id("my-key")
    .sign(jwt::algorithm::hs256("secret"), ec);

// Decode (does not verify)
auto decoded = jws::decode(token, ec);
std::string payload = decoded.get_payload();  // raw decoded bytes

// Verify signature
jws::verify()
    .allow_algorithm(jwt::algorithm::hs256("secret"))
    .verify(decoded, ec);
```

**Supported algorithms:** same as `jwt/` – HS256/384/512, RS256/384/512,
PS256/384/512, ES256/384/512, none (all from `jwt::algorithm::`).

**Relationship to JWT:** `jws::basic_jws` inherits `jwt::basic_header` and
therefore exposes the same `get_algorithm()`, `get_type()`, `get_key_id()`, …
accessors. The JWT library is a JWS whose payload is parsed as a JSON claims set.

---

### `jwt/` – JSON Web Token (RFC 7519 / 7515)

Signing and verification of compact JWS tokens.

```cpp
#include <jose/jwt/jwt_botan_jsoncons.hpp>

// Create
std::error_code ec;
std::string token = jwt::create()
    .set_issuer("VirtualDriver")
    .set_payload_claim("data", jwt::claim(std::string("hello")))
    .sign(jwt::algorithm::hs256("my-secret"), ec);

// Verify
auto decoded = jwt::decode(token, ec);
jwt::verify()
    .with_issuer("VirtualDriver")
    .allow_algorithm(jwt::algorithm::hs256("my-secret"))
    .verify(decoded, ec);
```

**Supported algorithms:** HS256/384/512, RS256/384/512, PS256/384/512, ES256/384/512, none.

---

### `jwk/` – JSON Web Key (RFC 7517)

Represent, import, and export cryptographic keys in JSON format.

```cpp
#include <jose/jwk/jwk_botan_jsoncons.hpp>

std::error_code ec;

// From PEM
auto key = jwk::from_pem_public(pem_str, ec, "my-key-id");
auto key = jwk::from_pem_private(pem_str, ec, "my-key-id");

// From raw bytes (symmetric)
auto key = jwk::from_secret(secret_bytes, ec, "sym-1", "A256GCM");

// From JSON
auto key = jwk::from_json(json_str, ec);

// Export
std::string pem_pub  = key.to_pem_public(ec);
std::string pem_priv = key.to_pem_private(ec);
std::string raw      = key.to_secret(ec);

// Key Set
jwk::jwks ks;
ks.add_key(key);
auto found = ks.find_by_kid("my-key-id");
std::string json = ks.to_json();
```

**Supported key types:** `oct` (symmetric), `RSA`, `EC` (P-256, P-384, P-521).

---

### `jwe/` – JSON Web Encryption (RFC 7516)

Authenticated encryption of arbitrary payloads in compact serialization.

```cpp
#include <jose/jwe/jwe_botan_jsoncons.hpp>
using namespace jwe::algorithm;

std::error_code ec;
const std::string kek(32, 'K');

// Encrypt
std::string token = jwe::create()
    .set_payload("sensitive data")
    .set_key_id("my-key")
    .encrypt(A256KW(kek), A256GCM{}, ec);

// Decrypt
auto decoded = jwe::decode(token, ec);
decoded.decrypt(A256KW(kek), A256GCM{}, ec);
std::string plaintext = decoded.get_plaintext(ec);

// Direct encryption (no key wrapping)
std::string token2 = jwe::create()
    .set_payload("data")
    .encrypt(dir(raw_cek_32_bytes), A256GCM{}, ec);
```

**Key management (`alg`):** `dir`, `RSA-OAEP`, `RSA-OAEP-256`,
`A128KW`, `A192KW`, `A256KW`, `A128GCMKW`, `A192GCMKW`, `A256GCMKW`.

**Content encryption (`enc`):** `A128GCM`, `A192GCM`, `A256GCM`,
`A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512`.

---

## Requirements

| Dependency | Tested version | Notes |
|---|---|---|
| C++ compiler | Apple Clang 16 / GCC / MSVC | C++20 required |
| CMake | ≥ 3.30 | only for the test suite |
| [Botan](https://botan.randombit.net/) | 3.12.0 | downloaded automatically by `FindBotan.cmake` |
| [jsoncons](https://github.com/danielaparker/jsoncons) | 1.7.0 | downloaded automatically by `FindJsoncons.cmake` |

Both dependencies can be supplied as local paths via `Botan_PATH` and `Jsoncons_PATH`
CMake cache variables instead of being downloaded.

---

## Tests

The test suite lives in `tests/` and is driven by CMake. The custom Find modules
in `tests/cmake/` download and configure Botan (amalgamation build) and jsoncons
(header-only) automatically — no prior installation needed.

```sh
cd tests
cmake -S . -B build
cmake --build build --config Release

./build/test_jwt   # JWT  – 112 tests
./build/test_jws   # JWS  –  74 tests
./build/test_jwk   # JWK  –  49 tests
./build/test_jwe   # JWE  –  67 tests
```

To use local copies of the dependencies instead of downloading them:

```sh
cmake -S . -B build \
    -DBotan_PATH=/path/to/botan-src \
    -DJsoncons_PATH=/path/to/jsoncons-src
```

---



## Directory layout

```
include/jose/
├── detail/                              ← Internal implementation details (not public API)
│   └── botan_include.hpp               Botan include bridge: amalgamation or modular headers
├── traits/                              ← Layer 1: concepts + crypto/json backends
│   ├── concepts.hpp                     C++20 concepts (JsonTraits, CryptoTraits, …)
│   ├── botan_crypto_traits.hpp          Base64url + botan_crypto_traits struct
│   └── jsoncons_json_traits.hpp         JSON backend (jsoncons)
├── jwk/                                 ← Layer 2: key management
│   ├── jwk.hpp                          basic_jwk / basic_jwks templates
│   ├── jwk_error.hpp
│   └── jwk_botan_jsoncons.hpp
├── algorithms/                          ← Layer 3: sign/verify algorithms
│   ├── botan_algorithms.hpp             jwt::algorithm::* (hs256, rs256, es256, …)
│   └── botan_algorithms_jwk.hpp         Bridge: JWK → algorithm (jose::algorithm::make_*)
├── jwt/                                 ← Layer 4: token operations
│   ├── jwt.hpp                          Core templates (basic_claim, basic_builder, …)
│   ├── jwt_error.hpp                    Error codes
│   ├── jwt_botan_jsoncons.hpp           Ready-to-use aliases and free functions
├── jws/
│   ├── jws.hpp                          basic_jws / basic_jws_builder / basic_jws_verifier
│   ├── jws_error.hpp
│   └── jws_botan_jsoncons.hpp
└── jwe/
    ├── jwe.hpp                          basic_jwe / basic_jwe_builder templates
    ├── jwe_error.hpp
    ├── jwe_botan_jsoncons.hpp
    ├── algorithms/
    │   └── botan_jwe_algorithms.hpp     Key-management + content-encryption impls
```

## Layer diagram

```
traits/      ← Layer 1: concepts + crypto/json backends
    ↑
jwk/         ← Layer 2: key management
    ↑
algorithms/  ← Layer 3: sign/verify/wrap algorithms
    ↑
jwt/ jws/ jwe/ ← Layer 4: token operations
```

## Design principles

- **Header-only** – include and go, no compilation step.
- **Traits-based** – JSON and crypto backends are pluggable via C++20 concepts.
- **`std::error_code` throughout** – no exceptions by default; use
  `throw_if_error(ec)` to convert when needed.
- **Shared backends** – JWK and JWE reuse `traits/` directly.
- **Composable** – pair any `JweAlgConcept` algorithm with any
  `JweEncConcept` algorithm at the call site.
