#pragma once

/**
 * Convenience glue header: wires jwe core (basic_* templates) with the
 * jsoncons JSON backend and the Botan crypto backend.
 *
 * Include this header to get the ready-to-use jwe::jwe / jwe::builder aliases
 * and the jwe::create() / jwe::decode() free functions.
 *
 * Also exposes jwe::algorithm:: for all Botan-backed key-management and
 * content-encryption algorithm implementations.
 *
 * Reuses the same traits already used by the jwt:: library.
 */

#include <jose/jwe/jwe.hpp>
#include <jose/jwe/algorithms/botan_jwe_algorithms.hpp>
#include <jose/traits/jsoncons_json_traits.hpp>
#include <jose/traits/botan_crypto_traits.hpp>
#include <jose/algorithms/botan_algorithms.hpp>

namespace jwe
{

    // ── Type aliases ──────────────────────────────────────────────────────────

    using header  = basic_jwe_header <jwt::traits::jsoncons_json_traits, jwt::traits::botan_crypto_traits>;
    using jwe     = basic_jwe        <jwt::traits::jsoncons_json_traits, jwt::traits::botan_crypto_traits>;
    using builder = basic_jwe_builder<jwt::traits::jsoncons_json_traits, jwt::traits::botan_crypto_traits>;

    // ── Free functions ────────────────────────────────────────────────────────

    /// Return a builder instance to create a new encrypted token.
    inline builder create()
    {
        return builder{};
    }

    /// Parse a compact JWE token string (does not decrypt).
    inline jwe decode(const std::string &token, std::error_code &ec)
    {
        return jwe(token, ec);
    }

} // namespace jwe
