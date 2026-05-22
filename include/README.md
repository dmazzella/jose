# include/jose — Header Reference

All headers are C++20, header-only, and require no compilation step.
The library is layered: each group depends only on groups listed above it.

---

## Layer 0 — Detail

### `detail/botan_include.hpp`
Botan include bridge. Detects at compile time whether a Botan amalgamation
(`<botan/botan_all.h>` or `<botan/botan.h>`) is available and falls back to
individual per-feature headers otherwise. Every other header that needs Botan
includes this file instead of Botan directly.

---

## Layer 1 — Traits

### `traits/concepts.hpp`
C++20 concepts that define the interfaces backends must satisfy:
- `JsonTraitsConcept` — static interface for JSON value construction, type
  inspection, conversion, array/object manipulation, and serialization.
- `CryptoTraitsConcept` — static interface for base64url encode/decode.

### `traits/botan_crypto_traits.hpp`
Botan implementation of `CryptoTraitsConcept`. Also defines:
- `JWT_ALG_HS256 … JWT_ALG_ES512` integer constants.
- `jwt::utils::hash_name_from_alg()` — maps an algorithm ID to a Botan hash
  name string (`"SHA-256"`, `"SHA-384"`, `"SHA-512"`).

### `traits/jsoncons_json_traits.hpp`
jsoncons implementation of `JsonTraitsConcept` (`jsoncons_json_traits`). Wraps
`jsoncons::json` as `value_type` and implements all required static methods for
construction, type inspection, conversion, and serialization.

---

## Layer 2 — JWK

### `jwk/jwk_error.hpp`
Error infrastructure for JWK operations. Defines:
- `jwk_error` enum — `invalid_key_type`, `missing_required_parameter`,
  `unsupported_curve`, `key_import_failed`, `key_export_failed`, etc.
- `std::error_category` registration so `jwk_error` values integrate with
  `std::error_code`.

### `jwk/jwk.hpp`
Core JWK templates (RFC 7517). Defines:
- `key_type` — `oct`, `RSA`, `EC`.
- `ec_curve` — `P256`, `P384`, `P521`.
- `basic_jwk<JsonTraits, CryptoTraits>` — single JSON Web Key with accessors
  for all RFC 7517 parameters (`kty`, `kid`, `use`, `alg`, `n`/`e`/`d`/…,
  `crv`/`x`/`y`, `k`) and converters: `to_pem_public()`, `to_pem_private()`,
  `to_secret()`, `from_pem_public()`, `from_pem_private()`, `from_secret()`.
- `basic_jwks<JsonTraits, CryptoTraits>` — key set (`{"keys":[…]}`) with
  `add_key()`, `find_by_kid()`, `to_json()`, and `from_jwks_json()`.

### `jwk/jwk_botan_jsoncons.hpp`
Ready-to-use aliases for the Botan + jsoncons backend:
```cpp
jwk::jwk   // basic_jwk<jsoncons_json_traits, botan_crypto_traits>
jwk::jwks  // basic_jwks<...>
```
Free functions: `from_json()`, `from_pem_public()`, `from_pem_private()`,
`from_secret()`, `from_jwks_json()`.

---

## Layer 3 — Algorithms

### `algorithms/botan_algorithms.hpp`
All `jwt::algorithm::*` sign/verify implementations backed by Botan:
- `none` — no-op algorithm.
- `hmacsha` base + `hs256`, `hs384`, `hs512` — HMAC-SHA family.
- `rsa` base + `rs256`, `rs384`, `rs512` — RSASSA-PKCS1-v1_5.
- `pss` base + `ps256`, `ps384`, `ps512` — RSASSA-PSS.
- `ecdsa` base + `es256`, `es384`, `es512`, `es256k` — ECDSA.

Each algorithm type exposes `sign()`, `verify()`, and `name()`.

### `algorithms/botan_algorithms_jwk.hpp`
Bridge between JWK keys and JWT algorithms. Provides:
- `any_algorithm` — `std::variant` over all concrete algorithm types.
- Typed factories: `make_hs256(key, ec)`, `make_rs256(key, ec)`,
  `make_es256(key, ec)`, etc.
- `make_algorithm(key, ec)` — dispatches on the `"alg"` field of a JWK and
  returns the correct `any_algorithm` variant.

---

## Layer 4 — Token operations

### `jwt/jwt_error.hpp`
Error infrastructure for JWT/JWS operations. Defines exception types
(`signature_verification_exception`, `signature_generation_exception`,
`token_verification_exception`, …) and error enums:
- `rsa_error`, `ecdsa_error` — key and signature operation failures.
- `signature_verification_error` — verification-time failures (expired, bad
  issuer, invalid signature, wrong algorithm, …).
- `signature_generation_error` — signing failures.

### `jwt/jwt.hpp`
Core JWT templates (RFC 7519). Defines:
- `basic_claim<JsonTraits>` — typed JSON value wrapper with enum `type` tag.
- `basic_header<JsonTraits, CryptoTraits>` — decoded JOSE header (`alg`, `typ`,
  `kid`, `cty`, plus arbitrary custom header claims).
- `basic_decoded_jwt<JsonTraits, CryptoTraits>` — fully parsed compact token;
  exposes all standard claims (`iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`)
  and arbitrary payload/header claims.
- `basic_builder<JsonTraits, CryptoTraits>` — fluent builder for creating and
  signing tokens.
- `basic_verifier<Clock, JsonTraits, CryptoTraits>` — fluent verifier with
  `with_issuer()`, `with_audience()`, `allow_algorithm()`, leeway, etc.

### `jwt/jwt_botan_jsoncons.hpp`
Ready-to-use aliases and free functions for the Botan + jsoncons backend:
```cpp
jwt::claim        // basic_claim<jsoncons_json_traits>
jwt::decoded_jwt  // basic_decoded_jwt<...>
jwt::builder      // basic_builder<...>
jwt::verifier<C>  // basic_verifier<C, ...>

jwt::create()     // → builder
jwt::decode(token, ec) // → decoded_jwt
jwt::verify()     // → verifier<std::chrono::system_clock>
```

### `jws/jws_error.hpp`
Error codes for JWS operations. Defines `jws_error` enum (malformed token,
invalid base64, signature mismatch, etc.) and its `std::error_category`.

### `jws/jws.hpp`
Core JWS templates (RFC 7515). JWS signs arbitrary byte payloads; JWT is a
specialization where the payload is a JSON claims set. Defines:
- `basic_jws<JsonTraits, CryptoTraits>` — parsed compact JWS token; exposes
  raw payload bytes and header claims.
- `basic_jws_builder<JsonTraits, CryptoTraits>` — fluent builder with
  `set_payload()`, `set_type()`, `set_key_id()`, `set_header_claim()`, `sign()`.
- `basic_jws_verifier<JsonTraits, CryptoTraits>` — verifier with
  `allow_algorithm()` and `verify()`.

### `jws/jws_botan_jsoncons.hpp`
Ready-to-use aliases and free functions for the Botan + jsoncons backend:
```cpp
jws::jws      // basic_jws<...>
jws::create() // → basic_jws_builder
jws::decode(token, ec)
jws::verify() // → basic_jws_verifier
```

### `jwe/jwe_error.hpp`
Error codes for JWE operations. Defines `jwe_error` enum (bad token structure,
key wrap failure, decryption failure, unsupported algorithm, etc.) and its
`std::error_category`.

### `jwe/algorithms/botan_jwe_algorithms.hpp`
All JWE algorithm implementations backed by Botan.

Key management (`JweAlgConcept`):
- `dir` — direct encryption (CEK is the provided key, no wrapping).
- `RSA_OAEP`, `RSA_OAEP_256` — RSAES-OAEP with SHA-1 / SHA-256.
- `A128KW`, `A192KW`, `A256KW` — AES Key Wrap (RFC 3394).
- `A128GCMKW`, `A192GCMKW`, `A256GCMKW` — AES-GCM Key Wrap.

Content encryption (`JweEncConcept`):
- `A128GCM`, `A192GCM`, `A256GCM` — AES-GCM AEAD.
- `A128CBC_HS256`, `A192CBC_HS384`, `A256CBC_HS512` — AES-CBC + HMAC-SHA.

Each type exposes `wrap_key()` / `unwrap_key()` (alg) or
`encrypt()` / `decrypt()` (enc).

### `jwe/jwe.hpp`
Core JWE templates (RFC 7516). Compact serialization:
`BASE64URL(header).BASE64URL(encrypted_key).BASE64URL(iv).BASE64URL(ciphertext).BASE64URL(tag)`

Defines:
- `basic_jwe<JsonTraits, CryptoTraits>` — decoded JWE token; exposes header
  claims and `decrypt(alg, enc, ec)` / `get_plaintext(ec)`.
- `basic_jwe_builder<JsonTraits, CryptoTraits>` — fluent builder with
  `set_payload()`, `set_key_id()`, `set_header_claim()`, `encrypt(alg, enc, ec)`.

### `jwe/jwe_botan_jsoncons.hpp`
Ready-to-use aliases and free functions for the Botan + jsoncons backend:
```cpp
jwe::jwe      // basic_jwe<...>
jwe::create() // → basic_jwe_builder
jwe::decode(token, ec)
```
Also re-exports all algorithm types under `jwe::algorithm::`.
