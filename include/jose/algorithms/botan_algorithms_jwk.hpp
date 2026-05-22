#pragma once

/**
 * Bridge: JWK → jwt::algorithm::*
 *
 * This file sits above both algorithms/ and jwk/ in the dependency stack.
 * It is the ONLY file that depends on both.
 *
 * Include this to get:
 *   jose::algorithm::make_hs256(key, ec)
 *   jose::algorithm::make_rs256(key, ec)
 *   jose::algorithm::make_es256(key, ec)
 *   jose::algorithm::make_algorithm(key, ec)   // dispatches on JWK "alg" field
 */

#include <jose/algorithms/botan_algorithms.hpp>
#include <jose/jwk/jwk_botan_jsoncons.hpp>

#include <optional>
#include <string>
#include <system_error>
#include <variant>

namespace jose::algorithm
{
    // ── Type alias for all supported algorithms ────────────────────────────────
    using any_algorithm = std::variant<
        jwt::algorithm::none,
        jwt::algorithm::hs256, jwt::algorithm::hs384, jwt::algorithm::hs512,
        jwt::algorithm::rs256, jwt::algorithm::rs384, jwt::algorithm::rs512,
        jwt::algorithm::es256, jwt::algorithm::es384, jwt::algorithm::es512,
        jwt::algorithm::ps256, jwt::algorithm::ps384, jwt::algorithm::ps512
    >;

    // ── Typed factories ────────────────────────────────────────────────────────

    inline jwt::algorithm::hs256
    make_hs256(const jwk::jwk& key, std::error_code& ec)
    {
        std::error_code ec2;
        auto kty = key.get_key_type(ec2);
        if (ec2 || kty != jwk::key_type::oct) {
            ec = jwk::error::make_error_code(jwk::error::jwk_error::invalid_key_type);
            return jwt::algorithm::hs256{""};
        }
        std::string secret = key.to_secret(ec2);
        if (ec2) { ec = ec2; return jwt::algorithm::hs256{""}; }
        return jwt::algorithm::hs256{secret};
    }

    inline jwt::algorithm::hs384 make_hs384(const jwk::jwk& key, std::error_code& ec)
    {
        std::error_code ec2;
        auto kty = key.get_key_type(ec2);
        if (ec2 || kty != jwk::key_type::oct) {
            ec = jwk::error::make_error_code(jwk::error::jwk_error::invalid_key_type);
            return jwt::algorithm::hs384{""};
        }
        std::string secret = key.to_secret(ec2);
        if (ec2) { ec = ec2; return jwt::algorithm::hs384{""}; }
        return jwt::algorithm::hs384{secret};
    }

    inline jwt::algorithm::hs512 make_hs512(const jwk::jwk& key, std::error_code& ec)
    {
        std::error_code ec2;
        auto kty = key.get_key_type(ec2);
        if (ec2 || kty != jwk::key_type::oct) {
            ec = jwk::error::make_error_code(jwk::error::jwk_error::invalid_key_type);
            return jwt::algorithm::hs512{""};
        }
        std::string secret = key.to_secret(ec2);
        if (ec2) { ec = ec2; return jwt::algorithm::hs512{""}; }
        return jwt::algorithm::hs512{secret};
    }

    inline jwt::algorithm::rs256
    make_rs256(const jwk::jwk& key, std::error_code& ec)
    {
        std::error_code ec2;
        std::string pub = key.to_pem_public(ec2);
        if (ec2) { ec = ec2; return jwt::algorithm::rs256{"", ""}; }
        std::string priv;
        if (key.has_d()) { priv = key.to_pem_private(ec2); if (ec2) { ec = ec2; return jwt::algorithm::rs256{"", ""}; } }
        return jwt::algorithm::rs256{pub, priv};
    }

    inline jwt::algorithm::rs384 make_rs384(const jwk::jwk& key, std::error_code& ec)
    {
        std::error_code ec2;
        std::string pub = key.to_pem_public(ec2); if (ec2) { ec = ec2; return jwt::algorithm::rs384{"",""}; }
        std::string priv; if (key.has_d()) { priv = key.to_pem_private(ec2); if (ec2) { ec = ec2; return jwt::algorithm::rs384{"",""}; } }
        return jwt::algorithm::rs384{pub, priv};
    }

    inline jwt::algorithm::rs512 make_rs512(const jwk::jwk& key, std::error_code& ec)
    {
        std::error_code ec2;
        std::string pub = key.to_pem_public(ec2); if (ec2) { ec = ec2; return jwt::algorithm::rs512{"",""}; }
        std::string priv; if (key.has_d()) { priv = key.to_pem_private(ec2); if (ec2) { ec = ec2; return jwt::algorithm::rs512{"",""}; } }
        return jwt::algorithm::rs512{pub, priv};
    }

    inline jwt::algorithm::es256
    make_es256(const jwk::jwk& key, std::error_code& ec)
    {
        std::error_code ec2;
        std::string pub = key.to_pem_public(ec2); if (ec2) { ec = ec2; return jwt::algorithm::es256{"",""}; }
        std::string priv; if (key.has_d()) { priv = key.to_pem_private(ec2); if (ec2) { ec = ec2; return jwt::algorithm::es256{"",""}; } }
        return jwt::algorithm::es256{pub, priv};
    }

    inline jwt::algorithm::es384 make_es384(const jwk::jwk& key, std::error_code& ec)
    {
        std::error_code ec2;
        std::string pub = key.to_pem_public(ec2); if (ec2) { ec = ec2; return jwt::algorithm::es384{"",""}; }
        std::string priv; if (key.has_d()) { priv = key.to_pem_private(ec2); if (ec2) { ec = ec2; return jwt::algorithm::es384{"",""}; } }
        return jwt::algorithm::es384{pub, priv};
    }

    inline jwt::algorithm::es512 make_es512(const jwk::jwk& key, std::error_code& ec)
    {
        std::error_code ec2;
        std::string pub = key.to_pem_public(ec2); if (ec2) { ec = ec2; return jwt::algorithm::es512{"",""}; }
        std::string priv; if (key.has_d()) { priv = key.to_pem_private(ec2); if (ec2) { ec = ec2; return jwt::algorithm::es512{"",""}; } }
        return jwt::algorithm::es512{pub, priv};
    }

    inline jwt::algorithm::ps256 make_ps256(const jwk::jwk& key, std::error_code& ec)
    {
        std::error_code ec2;
        std::string pub = key.to_pem_public(ec2); if (ec2) { ec = ec2; return jwt::algorithm::ps256{"",""}; }
        std::string priv; if (key.has_d()) { priv = key.to_pem_private(ec2); if (ec2) { ec = ec2; return jwt::algorithm::ps256{"",""}; } }
        return jwt::algorithm::ps256{pub, priv};
    }

    inline jwt::algorithm::ps384 make_ps384(const jwk::jwk& key, std::error_code& ec)
    {
        std::error_code ec2;
        std::string pub = key.to_pem_public(ec2); if (ec2) { ec = ec2; return jwt::algorithm::ps384{"",""}; }
        std::string priv; if (key.has_d()) { priv = key.to_pem_private(ec2); if (ec2) { ec = ec2; return jwt::algorithm::ps384{"",""}; } }
        return jwt::algorithm::ps384{pub, priv};
    }

    inline jwt::algorithm::ps512 make_ps512(const jwk::jwk& key, std::error_code& ec)
    {
        std::error_code ec2;
        std::string pub = key.to_pem_public(ec2); if (ec2) { ec = ec2; return jwt::algorithm::ps512{"",""}; }
        std::string priv; if (key.has_d()) { priv = key.to_pem_private(ec2); if (ec2) { ec = ec2; return jwt::algorithm::ps512{"",""}; } }
        return jwt::algorithm::ps512{pub, priv};
    }

    // ── Dynamic factory — dispatches on JWK "alg" field ───────────────────────
    inline any_algorithm
    make_algorithm(const jwk::jwk& key,
                   std::error_code& ec,
                   std::optional<std::string> alg_override = std::nullopt)
    {
        std::error_code ec2;
        std::string alg_name;
        if (alg_override) {
            alg_name = *alg_override;
        } else if (key.has_algorithm()) {
            alg_name = key.get_algorithm(ec2);
            if (ec2) { ec = ec2; return jwt::algorithm::none{}; }
        } else {
            ec = jwk::error::make_error_code(jwk::error::jwk_error::missing_required_parameter);
            return jwt::algorithm::none{};
        }

        if (alg_name == "HS256") return make_hs256(key, ec);
        if (alg_name == "HS384") return make_hs384(key, ec);
        if (alg_name == "HS512") return make_hs512(key, ec);
        if (alg_name == "RS256") return make_rs256(key, ec);
        if (alg_name == "RS384") return make_rs384(key, ec);
        if (alg_name == "RS512") return make_rs512(key, ec);
        if (alg_name == "ES256") return make_es256(key, ec);
        if (alg_name == "ES384") return make_es384(key, ec);
        if (alg_name == "ES512") return make_es512(key, ec);
        if (alg_name == "PS256") return make_ps256(key, ec);
        if (alg_name == "PS384") return make_ps384(key, ec);
        if (alg_name == "PS512") return make_ps512(key, ec);

        ec = jwk::error::make_error_code(jwk::error::jwk_error::unsupported_key_type);
        return jwt::algorithm::none{};
    }

} // namespace jose::algorithm
