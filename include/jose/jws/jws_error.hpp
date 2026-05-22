#pragma once

#include <system_error>
#include <string>

namespace jws
{

namespace error
{
    // ── Exception type ────────────────────────────────────────────────────────

    struct jws_exception : public std::system_error
    {
        using system_error::system_error;
    };

    // ── jws_error ─────────────────────────────────────────────────────────────
    //
    // Signature-level errors (invalid_signature, etc.) are reported via the
    // jwt::error::signature_verification_error category, since JWS reuses the
    // same algorithm implementations from jwt/traits/botan_crypto_traits.hpp.

    enum class jws_error
    {
        ok = 0,
        invalid_token = 10,  ///< Malformed compact token (wrong number of parts, bad base64)
        unknown_algorithm,   ///< Algorithm in header not registered with the verifier
        invalid_base64url,   ///< A part of the token cannot be base64url-decoded
    };

    inline std::error_category &jws_error_category()
    {
        class cat_t : public std::error_category
        {
        public:
            const char *name() const noexcept override { return "jws_error"; }
            std::string message(int ev) const override
            {
                switch (static_cast<jws_error>(ev))
                {
                case jws_error::ok:                return "no error";
                case jws_error::invalid_token:     return "invalid JWS compact token";
                case jws_error::unknown_algorithm: return "unknown or disallowed algorithm";
                case jws_error::invalid_base64url: return "invalid base64url encoding";
                default:                           return "unknown JWS error";
                }
            }
        };
        static cat_t cat;
        return cat;
    }

    inline std::error_code make_error_code(jws_error e)
    {
        return {static_cast<int>(e), jws_error_category()};
    }

    inline void throw_if_error(std::error_code ec)
    {
        if (!ec) return;
        throw jws_exception(ec);
    }

} // namespace error

} // namespace jws

namespace std
{
    template <> struct is_error_code_enum<jws::error::jws_error> : true_type {};
} // namespace std
