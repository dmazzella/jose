#pragma once

#include <optional>
#include <span>
#include <memory>
#include <cstdint>
#include <string>

#include <jose/detail/botan_include.hpp>
#include <jose/traits/concepts.hpp>
#include <jose/jwt/jwt_error.hpp>

namespace jwt
{

    // ── Algorithm ID constants ─────────────────────────────────────────────────

    constexpr uint8_t JWT_ALG_HS256 = 1;
    constexpr uint8_t JWT_ALG_RS256 = 2;
    constexpr uint8_t JWT_ALG_PS256 = 3;
    constexpr uint8_t JWT_ALG_ES256 = 4;
    constexpr uint8_t JWT_ALG_ES256K = 5;
    constexpr uint8_t JWT_ALG_HS384 = 6;
    constexpr uint8_t JWT_ALG_RS384 = 7;
    constexpr uint8_t JWT_ALG_PS384 = 8;
    constexpr uint8_t JWT_ALG_ES384 = 9;
    constexpr uint8_t JWT_ALG_HS512 = 10;
    constexpr uint8_t JWT_ALG_RS512 = 11;
    constexpr uint8_t JWT_ALG_PS512 = 12;
    constexpr uint8_t JWT_ALG_ES512 = 13;

    // ── Internal hash-name helper ──────────────────────────────────────────────

    namespace utils
    {
        inline std::string hash_name_from_alg(const int alg)
        {
            switch (alg)
            {
            case JWT_ALG_HS256:
            case JWT_ALG_RS256:
            case JWT_ALG_PS256:
            case JWT_ALG_ES256:
            case JWT_ALG_ES256K:
                return "SHA-256";
            case JWT_ALG_HS384:
            case JWT_ALG_RS384:
            case JWT_ALG_PS384:
            case JWT_ALG_ES384:
                return "SHA-384";
            case JWT_ALG_HS512:
            case JWT_ALG_RS512:
            case JWT_ALG_PS512:
            case JWT_ALG_ES512:
                return "SHA-512";
            default:
                return "";
            }
        }
    } // namespace utils

    // ── Base64 alphabet tags ───────────────────────────────────────────────────

    namespace alphabet
    {
        struct base64
        {
            static const std::string &fill()
            {
                static std::string fill = "=";
                return fill;
            }
        };
        struct base64url
        {
            static const std::string &fill()
            {
                static std::string fill = "=";
                return fill;
            }
        };
    } // namespace alphabet

    // ── Base64 / Base64url encode-decode backed by Botan ──────────────────────

    class base
    {
    public:
        template <typename T>
        static std::string encode(const std::string &bin)
        {
            const auto *data = reinterpret_cast<const uint8_t *>(bin.data());
            std::string result = Botan::base64_encode(data, bin.size());

            if constexpr (std::is_same_v<T, alphabet::base64url>)
            {
                for (char &c : result)
                {
                    if (c == '+')
                        c = '-';
                    else if (c == '/')
                        c = '_';
                }
                while (!result.empty() && result.back() == '=')
                    result.pop_back();
            }

            return result;
        }

        template <typename T>
        static std::string decode(const std::string &b64, std::error_code &ec)
        {
            std::string input = b64;

            if constexpr (std::is_same_v<T, alphabet::base64url>)
            {
                for (char &c : input)
                {
                    if (c == '-')
                        c = '+';
                    else if (c == '_')
                        c = '/';
                }
            }

            while (!input.empty() && input.back() == '=')
                input.pop_back();
            switch (input.size() % 4)
            {
            case 2:
                input += "==";
                break;
            case 3:
                input += "=";
                break;
            case 1:
                ec = error::internal_error::invalid_input;
                return "";
            default:
                break;
            }

            try
            {
                auto decoded = Botan::base64_decode(input);
                return std::string(decoded.begin(), decoded.end());
            }
            catch (...)
            {
                ec = error::internal_error::invalid_input;
                return "";
            }
        }
    };

    // ── botan_crypto_traits ───────────────────────────────────────────────────
    //
    // Minimal static interface required by jwt::basic_decoded_jwt and
    // jwt::basic_builder for base64url encode/decode operations.

    namespace traits
    {

        struct botan_crypto_traits
        {
            /// Encode binary data as base64url (no padding).
            static std::string base64url_encode(const std::string &data)
            {
                return base::encode<alphabet::base64url>(data);
            }

            /// Decode a base64url string; sets ec on failure.
            static std::string base64url_decode(const std::string &b64, std::error_code &ec)
            {
                return base::decode<alphabet::base64url>(b64, ec);
            }
        };

    } // namespace traits

} // namespace jwt
