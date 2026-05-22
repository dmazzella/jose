#pragma once

#include <system_error>
#include <string>

namespace jwk
{

namespace error
{
    // ── Exception type ────────────────────────────────────────────────────────

    struct jwk_exception : public std::system_error
    {
        using system_error::system_error;
    };

    // ── jwk_error ─────────────────────────────────────────────────────────────

    enum class jwk_error
    {
        ok = 0,
        invalid_key_type = 10,
        missing_required_parameter,
        invalid_parameter,
        unsupported_key_type,
        unsupported_curve,
        key_import_failed,
        key_export_failed,
        invalid_base64url,
        invalid_json,
    };

    inline std::error_category &jwk_error_category()
    {
        class cat_t : public std::error_category
        {
        public:
            const char *name() const noexcept override { return "jwk_error"; }
            std::string message(int ev) const override
            {
                switch (static_cast<jwk_error>(ev))
                {
                case jwk_error::ok:                         return "no error";
                case jwk_error::invalid_key_type:           return "invalid key type";
                case jwk_error::missing_required_parameter: return "missing required parameter";
                case jwk_error::invalid_parameter:          return "invalid parameter value";
                case jwk_error::unsupported_key_type:       return "unsupported key type";
                case jwk_error::unsupported_curve:          return "unsupported EC curve";
                case jwk_error::key_import_failed:          return "key import failed";
                case jwk_error::key_export_failed:          return "key export failed";
                case jwk_error::invalid_base64url:          return "invalid base64url encoding";
                case jwk_error::invalid_json:               return "invalid JSON";
                default:                                    return "unknown JWK error";
                }
            }
        };
        static cat_t cat;
        return cat;
    }

    inline std::error_code make_error_code(jwk_error e)
    {
        return {static_cast<int>(e), jwk_error_category()};
    }

    inline void throw_if_error(std::error_code ec)
    {
        if (!ec) return;
        throw jwk_exception(ec);
    }

} // namespace error

} // namespace jwk

namespace std
{
    template <> struct is_error_code_enum<jwk::error::jwk_error> : true_type {};
} // namespace std
