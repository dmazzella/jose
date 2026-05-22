#pragma once

/**
 * Botan-backed jwt::algorithm::* implementations.
 *
 * Provides all concrete sign/verify algorithm types:
 *   jwt::algorithm::none
 *   jwt::algorithm::hs256, hs384, hs512
 *   jwt::algorithm::rs256, rs384, rs512
 *   jwt::algorithm::es256, es384, es512
 *   jwt::algorithm::ps256, ps384, ps512
 *   jwt::algorithm::es256k (via ecdsa base)
 *
 * These depend on jwt::utils::hash_name_from_alg and the JWT_ALG_* constants
 * which are defined in <jose/traits/botan_crypto_traits.hpp>.
 */

#include <jose/traits/botan_crypto_traits.hpp>
#include <jose/jwt/jwt_error.hpp>

#include <jose/detail/botan_include.hpp>

#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace jwt
{
    namespace algorithm
    {
        /**
         * "none" algorithm.
         */
        struct none
        {
            none() {}

            std::string sign(const std::string &, std::error_code &) const
            {
                return "";
            }

            void verify(const std::string &, const std::string &signature, std::error_code &ec) const
            {
                if (!signature.empty())
                    ec = error::signature_verification_error::invalid_signature;
            }

            std::string name() const { return "none"; }
        };

        /**
         * Base class for HMAC family of algorithms.
         */
        struct hmacsha
        {
            hmacsha(std::string key, const std::string &name = "", const int id = JWT_ALG_HS256)
                : m_secret(std::move(key)), m_algorithmName(name), m_algorithmId(id)
            {
            }

            std::string sign(const std::string &data, std::error_code &ec) const
            {
                try
                {
                    const std::string hash_name = utils::hash_name_from_alg(m_algorithmId);
                    auto hmac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(" + hash_name + ")");
                    hmac->set_key(reinterpret_cast<const uint8_t *>(m_secret.data()), m_secret.size());
                    hmac->update(reinterpret_cast<const uint8_t *>(data.data()), data.size());
                    auto result = hmac->final();
                    return std::string(reinterpret_cast<const char *>(result.data()), result.size());
                }
                catch (const std::exception &)
                {
                    ec = error::signature_generation_error::hmac_failed;
                    return "";
                }
            }

            void verify(const std::string &data, const std::string &signature, std::error_code &ec) const
            {
                std::string signature_to_cmp = sign(data, ec);
                if (!ec && signature != signature_to_cmp)
                    ec = error::signature_verification_error::invalid_signature;
            }

            std::string name() const { return m_algorithmName; }

        private:
            const std::string m_secret;
            const std::string m_algorithmName;
            const int m_algorithmId;
        };

        /**
         * Base class for RSA PKCS1v15 family of algorithms.
         */
        struct rsa
        {
            rsa(const std::string &public_key,
                const std::string &private_key,
                const std::string &public_key_password = "",
                const std::string &private_key_password = "",
                const std::string &name = "",
                const int id = JWT_ALG_RS256)
                : m_publicKey(public_key), m_privateKey(private_key), m_publicKeyPassword(public_key_password.empty() ? std::nullopt : std::make_optional(public_key_password)), m_privateKeyPassword(private_key_password.empty() ? std::nullopt : std::make_optional(private_key_password)), m_algorithmName(name), m_algorithmId(id)
            {
            }

            std::string sign(const std::string &data, std::error_code &ec) const
            {
                try
                {
                    auto key_span = std::span<const uint8_t>(
                        reinterpret_cast<const uint8_t *>(m_privateKey.data()), m_privateKey.size());

                    std::unique_ptr<Botan::Private_Key> priv_key;
                    if (!m_privateKeyPassword)
                        priv_key = Botan::PKCS8::load_key(key_span);
                    else
                        priv_key = Botan::PKCS8::load_key(key_span, *m_privateKeyPassword);

                    if (priv_key->algo_name() != "RSA")
                    {
                        ec = error::rsa_error::incorrect_key_type;
                        return "";
                    }

                    const std::string padding = "PKCS1v15(" + utils::hash_name_from_alg(m_algorithmId) + ")";
                    Botan::AutoSeeded_RNG rng;
                    Botan::PK_Signer signer(*priv_key, rng, padding);
                    auto sig = signer.sign_message(
                        reinterpret_cast<const uint8_t *>(data.data()), data.size(), rng);

                    return std::string(reinterpret_cast<const char *>(sig.data()), sig.size());
                }
                catch (const std::exception &)
                {
                    ec = error::rsa_error::signature_generation;
                    return "";
                }
            }

            void verify(const std::string &data, const std::string &signature, std::error_code &ec) const
            {
                try
                {
                    auto key_bytes = std::vector<uint8_t>(m_publicKey.begin(), m_publicKey.end());
                    auto pub_key = Botan::X509::load_key(key_bytes);

                    if (pub_key->algo_name() != "RSA")
                    {
                        ec = error::rsa_error::incorrect_key_type;
                        return;
                    }

                    const std::string padding = "PKCS1v15(" + utils::hash_name_from_alg(m_algorithmId) + ")";
                    Botan::PK_Verifier verifier(*pub_key, padding);
                    const bool valid = verifier.verify_message(
                        reinterpret_cast<const uint8_t *>(data.data()), data.size(),
                        reinterpret_cast<const uint8_t *>(signature.data()), signature.size());

                    if (!valid)
                        ec = error::rsa_error::signature_verification;
                }
                catch (const std::exception &)
                {
                    ec = error::rsa_error::parse_key;
                }
            }

            std::string name() const { return m_algorithmName; }

        private:
            const std::string m_publicKey;
            const std::string m_privateKey;
            const std::optional<std::string> m_publicKeyPassword;
            const std::optional<std::string> m_privateKeyPassword;
            const std::string m_algorithmName;
            const int m_algorithmId;
        };

        /**
         * Base class for ECDSA family of algorithms.
         */
        struct ecdsa
        {
            ecdsa(const std::string &public_key,
                  const std::string &private_key,
                  const std::string &public_key_password = "",
                  const std::string &private_key_password = "",
                  const std::string &name = "",
                  const int id = JWT_ALG_ES256)
                : m_publicKey(public_key), m_privateKey(private_key), m_publicKeyPassword(public_key_password.empty() ? std::nullopt : std::make_optional(public_key_password)), m_privateKeyPassword(private_key_password.empty() ? std::nullopt : std::make_optional(private_key_password)), m_algorithmName(name), m_algorithmId(id)
            {
            }

        private:
            static std::string expected_curve_oid(const int alg)
            {
                switch (alg)
                {
                case JWT_ALG_ES256:
                    return "1.2.840.10045.3.1.7"; // P-256 (secp256r1)
                case JWT_ALG_ES256K:
                    return "1.3.132.0.10"; // secp256k1
                case JWT_ALG_ES384:
                    return "1.3.132.0.34"; // P-384 (secp384r1)
                case JWT_ALG_ES512:
                    return "1.3.132.0.35"; // P-521 (secp521r1)
                default:
                    return "";
                }
            }

        public:
            std::string sign(const std::string &data, std::error_code &ec) const
            {
                try
                {
                    auto key_span = std::span<const uint8_t>(
                        reinterpret_cast<const uint8_t *>(m_privateKey.data()), m_privateKey.size());

                    std::unique_ptr<Botan::Private_Key> priv_key;
                    if (!m_privateKeyPassword)
                        priv_key = Botan::PKCS8::load_key(key_span);
                    else
                        priv_key = Botan::PKCS8::load_key(key_span, *m_privateKeyPassword);

                    if (priv_key->algo_name() != "ECDSA")
                    {
                        ec = error::ecdsa_error::invalid_key;
                        return "";
                    }

                    const auto *ecdsa_key = dynamic_cast<const Botan::ECDSA_PrivateKey *>(priv_key.get());
                    const std::string curve_oid = ecdsa_key->domain().get_curve_oid().to_string();
                    if (curve_oid != expected_curve_oid(m_algorithmId))
                    {
                        ec = error::ecdsa_error::invalid_key;
                        return "";
                    }

                    const std::string hash_name = utils::hash_name_from_alg(m_algorithmId);
                    Botan::AutoSeeded_RNG rng;
                    Botan::PK_Signer signer(*priv_key, rng, hash_name, Botan::Signature_Format::Standard);
                    auto sig = signer.sign_message(
                        reinterpret_cast<const uint8_t *>(data.data()), data.size(), rng);

                    return std::string(reinterpret_cast<const char *>(sig.data()), sig.size());
                }
                catch (const std::exception &)
                {
                    ec = error::ecdsa_error::signature_generation;
                    return "";
                }
            }

            void verify(const std::string &data, const std::string &signature, std::error_code &ec) const
            {
                try
                {
                    auto key_bytes = std::vector<uint8_t>(m_publicKey.begin(), m_publicKey.end());
                    auto pub_key = Botan::X509::load_key(key_bytes);

                    if (pub_key->algo_name() != "ECDSA")
                    {
                        ec = error::ecdsa_error::invalid_key;
                        return;
                    }

                    const std::string hash_name = utils::hash_name_from_alg(m_algorithmId);
                    Botan::PK_Verifier verifier(*pub_key, hash_name, Botan::Signature_Format::Standard);
                    const bool valid = verifier.verify_message(
                        reinterpret_cast<const uint8_t *>(data.data()), data.size(),
                        reinterpret_cast<const uint8_t *>(signature.data()), signature.size());

                    if (!valid)
                        ec = error::signature_verification_error::invalid_signature;
                }
                catch (const std::exception &)
                {
                    ec = error::ecdsa_error::load_key_read;
                }
            }

            std::string name() const { return m_algorithmName; }

        private:
            const std::string m_publicKey;
            const std::string m_privateKey;
            const std::optional<std::string> m_publicKeyPassword;
            const std::optional<std::string> m_privateKeyPassword;
            const std::string m_algorithmName;
            const int m_algorithmId;
        };

        /**
         * Base class for RSA-PSS family of algorithms.
         */
        struct pss
        {
            pss(const std::string &public_key,
                const std::string &private_key,
                const std::string &public_key_password = "",
                const std::string &private_key_password = "",
                const std::string &name = "",
                const int id = JWT_ALG_PS256)
                : m_publicKey(public_key), m_privateKey(private_key), m_publicKeyPassword(public_key_password.empty() ? std::nullopt : std::make_optional(public_key_password)), m_privateKeyPassword(private_key_password.empty() ? std::nullopt : std::make_optional(private_key_password)), m_algorithmName(name), m_algorithmId(id)
            {
            }

            std::string sign(const std::string &data, std::error_code &ec) const
            {
                try
                {
                    auto key_span = std::span<const uint8_t>(
                        reinterpret_cast<const uint8_t *>(m_privateKey.data()), m_privateKey.size());

                    std::unique_ptr<Botan::Private_Key> priv_key;
                    if (!m_privateKeyPassword)
                        priv_key = Botan::PKCS8::load_key(key_span);
                    else
                        priv_key = Botan::PKCS8::load_key(key_span, *m_privateKeyPassword);

                    if (priv_key->algo_name() != "RSA")
                    {
                        ec = error::rsa_error::incorrect_key_type;
                        return "";
                    }

                    const std::string padding = "PSS(" + utils::hash_name_from_alg(m_algorithmId) + ")";
                    Botan::AutoSeeded_RNG rng;
                    Botan::PK_Signer signer(*priv_key, rng, padding);
                    auto sig = signer.sign_message(
                        reinterpret_cast<const uint8_t *>(data.data()), data.size(), rng);

                    return std::string(reinterpret_cast<const char *>(sig.data()), sig.size());
                }
                catch (const std::exception &)
                {
                    ec = error::rsa_error::signature_generation;
                    return "";
                }
            }

            void verify(const std::string &data, const std::string &signature, std::error_code &ec) const
            {
                try
                {
                    auto key_bytes = std::vector<uint8_t>(m_publicKey.begin(), m_publicKey.end());
                    auto pub_key = Botan::X509::load_key(key_bytes);

                    if (pub_key->algo_name() != "RSA")
                    {
                        ec = error::rsa_error::incorrect_key_type;
                        return;
                    }

                    const std::string padding = "PSS(" + utils::hash_name_from_alg(m_algorithmId) + ")";
                    Botan::PK_Verifier verifier(*pub_key, padding);
                    const bool valid = verifier.verify_message(
                        reinterpret_cast<const uint8_t *>(data.data()), data.size(),
                        reinterpret_cast<const uint8_t *>(signature.data()), signature.size());

                    if (!valid)
                        ec = error::rsa_error::signature_verification;
                }
                catch (const std::exception &)
                {
                    ec = error::rsa_error::parse_key;
                }
            }

            std::string name() const { return m_algorithmName; }

        private:
            const std::string m_publicKey;
            const std::string m_privateKey;
            const std::optional<std::string> m_publicKeyPassword;
            const std::optional<std::string> m_privateKeyPassword;
            const std::string m_algorithmName;
            const int m_algorithmId;
        };

        // ── Concrete algorithm types ───────────────────────────────────────────

        struct hs256 : public hmacsha
        {
            explicit hs256(std::string key) : hmacsha(std::move(key), "HS256", JWT_ALG_HS256) {}
        };
        struct hs384 : public hmacsha
        {
            explicit hs384(std::string key) : hmacsha(std::move(key), "HS384", JWT_ALG_HS384) {}
        };
        struct hs512 : public hmacsha
        {
            explicit hs512(std::string key) : hmacsha(std::move(key), "HS512", JWT_ALG_HS512) {}
        };

        struct rs256 : public rsa
        {
            rs256(const std::string &pub, const std::string &priv = "", const std::string &pp = "", const std::string &kp = "") : rsa(pub, priv, pp, kp, "RS256", JWT_ALG_RS256) {}
        };
        struct rs384 : public rsa
        {
            rs384(const std::string &pub, const std::string &priv = "", const std::string &pp = "", const std::string &kp = "") : rsa(pub, priv, pp, kp, "RS384", JWT_ALG_RS384) {}
        };
        struct rs512 : public rsa
        {
            rs512(const std::string &pub, const std::string &priv = "", const std::string &pp = "", const std::string &kp = "") : rsa(pub, priv, pp, kp, "RS512", JWT_ALG_RS512) {}
        };

        struct es256 : public ecdsa
        {
            es256(const std::string &pub, const std::string &priv = "", const std::string &pp = "", const std::string &kp = "") : ecdsa(pub, priv, pp, kp, "ES256", JWT_ALG_ES256) {}
        };
        struct es384 : public ecdsa
        {
            es384(const std::string &pub, const std::string &priv = "", const std::string &pp = "", const std::string &kp = "") : ecdsa(pub, priv, pp, kp, "ES384", JWT_ALG_ES384) {}
        };
        struct es512 : public ecdsa
        {
            es512(const std::string &pub, const std::string &priv = "", const std::string &pp = "", const std::string &kp = "") : ecdsa(pub, priv, pp, kp, "ES512", JWT_ALG_ES512) {}
        };

        struct ps256 : public pss
        {
            ps256(const std::string &pub, const std::string &priv = "", const std::string &pp = "", const std::string &kp = "") : pss(pub, priv, pp, kp, "PS256", JWT_ALG_PS256) {}
        };
        struct ps384 : public pss
        {
            ps384(const std::string &pub, const std::string &priv = "", const std::string &pp = "", const std::string &kp = "") : pss(pub, priv, pp, kp, "PS384", JWT_ALG_PS384) {}
        };
        struct ps512 : public pss
        {
            ps512(const std::string &pub, const std::string &priv = "", const std::string &pp = "", const std::string &kp = "") : pss(pub, priv, pp, kp, "PS512", JWT_ALG_PS512) {}
        };

    } // namespace algorithm

} // namespace jwt
