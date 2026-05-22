#pragma once

/**
 * Convenience glue header: wires jwk core (basic_* templates) with the
 * jsoncons JSON backend and the Botan crypto backend.
 *
 * Include this header to get the ready-to-use jwk::jwk / jwk::jwks aliases
 * and the jwk::from_json() / jwk::from_pem_public() / jwk::from_pem_private() /
 * jwk::from_secret() free functions.
 *
 * Reuses the same traits already used by the jwt:: library so the two
 * libraries share no duplicate code.
 */

#include <jose/jwk/jwk.hpp>
#include <jose/traits/jsoncons_json_traits.hpp>
#include <jose/traits/botan_crypto_traits.hpp>

namespace jwk
{

    // ── Type aliases ──────────────────────────────────────────────────────────

    using jwk  = basic_jwk <jwt::traits::jsoncons_json_traits, jwt::traits::botan_crypto_traits>;
    using jwks = basic_jwks<jwt::traits::jsoncons_json_traits, jwt::traits::botan_crypto_traits>;

    // ── Free functions ────────────────────────────────────────────────────────

    /// Parse a compact JWK JSON string ({"kty":…}).
    inline jwk from_json(const std::string &json_str, std::error_code &ec)
    {
        return jwk(json_str, ec);
    }

    /// Build a JWK from a PEM-encoded public key (RSA or EC).
    inline jwk from_pem_public(const std::string &pem,
                               std::error_code &ec,
                               const std::optional<std::string> &kid = std::nullopt)
    {
        return jwk::from_pem_public(pem, ec, kid);
    }

    /// Build a JWK from a PEM-encoded PKCS#8 private key (RSA or EC).
    inline jwk from_pem_private(const std::string &pem,
                                std::error_code &ec,
                                const std::optional<std::string> &kid = std::nullopt,
                                const std::string &password = "")
    {
        return jwk::from_pem_private(pem, ec, kid, password);
    }

    /// Build an oct JWK from raw symmetric key bytes.
    inline jwk from_secret(const std::string &key_bytes,
                           std::error_code &ec,
                           const std::optional<std::string> &kid = std::nullopt,
                           const std::optional<std::string> &alg = std::nullopt)
    {
        return jwk::from_secret(key_bytes, ec, kid, alg);
    }

    /// Parse a compact JWKS JSON string ({"keys":[…]}).
    inline jwks from_jwks_json(const std::string &json_str, std::error_code &ec)
    {
        return jwks(json_str, ec);
    }

} // namespace jwk
