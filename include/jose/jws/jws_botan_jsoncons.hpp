#pragma once

/**
 * Convenience glue header: wires jws core (basic_* templates) with the
 * jsoncons JSON backend and the Botan crypto backend.
 *
 * Include this header to get the ready-to-use jws::jws / jws::builder /
 * jws::verifier aliases and the jws::create() / jws::decode() / jws::verify()
 * free functions.
 *
 * All jwt::algorithm:: implementations (hs256, rs256, es256, …) work
 * directly with the JWS verifier and builder – no extra glue required.
 *
 * Reuses the same traits already used by the jwt:: library.
 */

#include <jose/jws/jws.hpp>
#include <jose/traits/jsoncons_json_traits.hpp>
#include <jose/traits/botan_crypto_traits.hpp>
#include <jose/algorithms/botan_algorithms.hpp>

namespace jws
{

    // ── Type aliases ──────────────────────────────────────────────────────────

    using jws      = basic_jws         <jwt::traits::jsoncons_json_traits, jwt::traits::botan_crypto_traits>;
    using builder  = basic_jws_builder <jwt::traits::jsoncons_json_traits, jwt::traits::botan_crypto_traits>;
    using verifier = basic_jws_verifier<jwt::traits::jsoncons_json_traits, jwt::traits::botan_crypto_traits>;

    // ── Free functions ────────────────────────────────────────────────────────

    /// Return a builder instance to create a new signed token.
    inline builder create()
    {
        return builder{};
    }

    /// Parse a compact JWS token string (does not verify the signature).
    inline jws decode(const std::string &token, std::error_code &ec)
    {
        return jws(token, ec);
    }

    /// Return a verifier instance.
    inline verifier verify()
    {
        return verifier{};
    }

} // namespace jws
