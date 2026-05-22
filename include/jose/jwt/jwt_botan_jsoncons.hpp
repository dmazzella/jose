#pragma once

/**
 * Convenience glue header: wires jwt core (basic_* templates) with the
 * jsoncons JSON backend and the Botan crypto backend.
 *
 * Include this header to get the ready-to-use jwt::claim, jwt::decoded_jwt,
 * jwt::builder, jwt::verifier aliases and the jwt::create() / jwt::decode() /
 * jwt::verify() free functions.
 *
 * To use a different backend, include jwt.hpp directly and instantiate the
 * basic_* templates with your own JsonTraits / CryptoTraits types.
 */

#include <jose/jwt/jwt.hpp>
#include <jose/traits/jsoncons_json_traits.hpp>
#include <jose/traits/botan_crypto_traits.hpp>
#include <jose/algorithms/botan_algorithms.hpp>

namespace jwt
{

    // ── Type aliases ──────────────────────────────────────────────────────────

    using claim = basic_claim<traits::jsoncons_json_traits>;
    using decoded_jwt = basic_decoded_jwt<traits::jsoncons_json_traits, traits::botan_crypto_traits>;
    using builder = basic_builder<traits::jsoncons_json_traits, traits::botan_crypto_traits>;

    template <typename Clock>
    using verifier = basic_verifier<Clock, traits::jsoncons_json_traits, traits::botan_crypto_traits>;

    // ── Free functions ────────────────────────────────────────────────────────

    /// Build a verifier with a custom clock.
    template <typename Clock>
    verifier<Clock> verify(Clock c)
    {
        return verifier<Clock>(c);
    }

    /// Build a verifier with the default system clock.
    inline verifier<default_clock> verify()
    {
        return verifier<default_clock>(default_clock{});
    }

    /// Return a builder instance to create a new token.
    inline builder create()
    {
        return builder{};
    }

    /// Decode a compact JWT string.
    inline decoded_jwt decode(const std::string &token, std::error_code &ec)
    {
        return decoded_jwt(token, ec);
    }

} // namespace jwt
