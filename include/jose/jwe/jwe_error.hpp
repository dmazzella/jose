#pragma once

#include <system_error>
#include <string>

namespace jwe
{

namespace error
{
    // ── Exception types ───────────────────────────────────────────────────────

    struct jwe_exception : public std::system_error { using system_error::system_error; };

    // ── jwe_error ─────────────────────────────────────────────────────────────

    enum class jwe_error
    {
        ok = 0,
        invalid_token = 10,
        unsupported_algorithm,
        key_wrap_failed,
        key_unwrap_failed,
        encryption_failed,
        decryption_failed,
        invalid_ciphertext,
        invalid_key_size,
        invalid_base64url,
        not_decrypted,
    };

    inline std::error_category &jwe_error_category()
    {
        class cat_t : public std::error_category
        {
        public:
            const char *name() const noexcept override { return "jwe_error"; }
            std::string message(int ev) const override
            {
                switch (static_cast<jwe_error>(ev))
                {
                case jwe_error::ok:                    return "no error";
                case jwe_error::invalid_token:         return "invalid JWE compact token";
                case jwe_error::unsupported_algorithm: return "unsupported algorithm";
                case jwe_error::key_wrap_failed:       return "key wrap (encryption) failed";
                case jwe_error::key_unwrap_failed:     return "key unwrap (decryption) failed";
                case jwe_error::encryption_failed:     return "content encryption failed";
                case jwe_error::decryption_failed:     return "content decryption failed";
                case jwe_error::invalid_ciphertext:    return "authentication tag mismatch";
                case jwe_error::invalid_key_size:      return "wrong key size for algorithm";
                case jwe_error::invalid_base64url:     return "invalid base64url encoding";
                case jwe_error::not_decrypted:         return "token has not been decrypted yet";
                default:                               return "unknown JWE error";
                }
            }
        };
        static cat_t cat;
        return cat;
    }

    inline std::error_code make_error_code(jwe_error e)
    {
        return {static_cast<int>(e), jwe_error_category()};
    }

    inline void throw_if_error(std::error_code ec)
    {
        if (!ec) return;
        throw jwe_exception(ec);
    }

} // namespace error

} // namespace jwe

namespace std
{
    template <> struct is_error_code_enum<jwe::error::jwe_error> : true_type {};
} // namespace std
