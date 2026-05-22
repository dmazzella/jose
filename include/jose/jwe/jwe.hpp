#pragma once

/**
 * Core header for JSON Web Encryption (JWE, RFC 7516) – compact serialization.
 *
 * Compact format:
 *   BASE64URL(Protected Header)
 *   . BASE64URL(Encrypted Key)
 *   . BASE64URL(IV)
 *   . BASE64URL(Ciphertext)
 *   . BASE64URL(Authentication Tag)
 *
 * The library uses two orthogonal algorithm concepts:
 *
 *   JweAlgConcept   – key management   (wraps / unwraps the Content Encryption Key)
 *   JweEncConcept   – content encryption (encrypt / decrypt the payload)
 *
 * Concrete algorithm implementations live in
 *   <jwe/algorithms/botan_jwe_algorithms.hpp>
 *
 * For the ready-to-use aliases and free functions, include
 *   <jwe/jwe_botan_jsoncons.hpp>
 */

#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>

#include <jose/jwt/jwt.hpp>       // JsonTraitsConcept, CryptoTraitsConcept
#include <jose/jwe/jwe_error.hpp>

namespace jwe
{

    // ── Concepts ──────────────────────────────────────────────────────────────

    /**
     * Key Management Algorithm concept.
     *
     * wrap(cek_size, ec)
     *   Generates a random CEK of `cek_size` bytes, encrypts it with the key
     *   stored in the algorithm object, and returns {encrypted_key, cek}.
     *   For "dir": ignores cek_size, returns {"", direct_key}.
     *
     * unwrap(encrypted_key, ec)
     *   Decrypts `encrypted_key` and returns the CEK.
     *   For "dir": ignores encrypted_key, returns the stored direct key.
     */
    template <typename T>
    concept JweAlgConcept =
        requires(const T &alg, size_t cek_size,
                 const std::string &encrypted_key, std::error_code &ec) {
            { alg.wrap(cek_size, ec) }         -> std::same_as<std::pair<std::string, std::string>>;
            { alg.unwrap(encrypted_key, ec) }  -> std::convertible_to<std::string>;
            { alg.name() }                     -> std::convertible_to<std::string>;
        };

    /**
     * Content Encryption Algorithm concept.
     *
     * encrypt(cek, iv, aad, plaintext, ec)  → {ciphertext, tag}
     * decrypt(cek, iv, aad, ciphertext, tag, ec) → plaintext
     * generate_iv(ec) → random IV of the correct size
     * cek_size()      → required CEK length in bytes
     * name()          → RFC algorithm name (e.g. "A256GCM")
     */
    template <typename T>
    concept JweEncConcept =
        requires(const T &enc,
                 const std::string &cek, const std::string &iv,
                 const std::string &aad, const std::string &data,
                 const std::string &tag, std::error_code &ec) {
            { enc.encrypt(cek, iv, aad, data, ec) } -> std::same_as<std::pair<std::string, std::string>>;
            { enc.decrypt(cek, iv, aad, data, tag, ec) } -> std::convertible_to<std::string>;
            { enc.generate_iv(ec) }  -> std::convertible_to<std::string>;
            { enc.cek_size() }       -> std::same_as<size_t>;
            { enc.name() }           -> std::convertible_to<std::string>;
        };


    // ── basic_jwe_header ──────────────────────────────────────────────────────

    /**
     * Exposes typed accessors for the JWE protected header claims.
     */
    template <jwt::JsonTraitsConcept JsonTraits, jwt::CryptoTraitsConcept CryptoTraits>
    class basic_jwe_header
    {
    protected:
        typename JsonTraits::value_type m_header;

        std::string get_string(const std::string &key, std::error_code &ec) const
        {
            for (const auto &elem : JsonTraits::object_range(m_header))
            {
                if (JsonTraits::elem_key(elem) == key)
                {
                    const auto &val = JsonTraits::elem_value(elem);
                    if (!JsonTraits::is_string(val))
                    {
                        ec = error::jwe_error::invalid_token;
                        return "";
                    }
                    return JsonTraits::as_string(val);
                }
            }
            ec = error::jwe_error::invalid_token;
            return "";
        }

        bool has_claim(const std::string &key) const
        {
            for (const auto &elem : JsonTraits::object_range(m_header))
                if (JsonTraits::elem_key(elem) == key) return true;
            return false;
        }

    public:
        basic_jwe_header() : m_header(JsonTraits::make_empty_object()) {}

        bool has_algorithm()   const { return has_claim("alg"); }
        bool has_enc()         const { return has_claim("enc"); }
        bool has_key_id()      const { return has_claim("kid"); }
        bool has_content_type()const { return has_claim("cty"); }

        std::string get_algorithm   (std::error_code &ec) const { return get_string("alg", ec); }
        std::string get_enc         (std::error_code &ec) const { return get_string("enc", ec); }
        std::string get_key_id      (std::error_code &ec) const { return get_string("kid", ec); }
        std::string get_content_type(std::error_code &ec) const { return get_string("cty", ec); }

        bool has_header_claim(const std::string &key) const { return has_claim(key); }

        typename JsonTraits::value_type
        get_header_claim(const std::string &key, std::error_code &ec) const
        {
            for (const auto &elem : JsonTraits::object_range(m_header))
                if (JsonTraits::elem_key(elem) == key)
                    return JsonTraits::elem_value(elem);
            ec = error::jwe_error::invalid_token;
            return JsonTraits::make_empty_object();
        }
    };


    // ── basic_jwe ─────────────────────────────────────────────────────────────

    /**
     * A parsed (but not yet decrypted) JWE compact token.
     *
     * After construction, call decrypt<AlgType, EncType>() then get_plaintext().
     */
    template <jwt::JsonTraitsConcept JsonTraits, jwt::CryptoTraitsConcept CryptoTraits>
    class basic_jwe : public basic_jwe_header<JsonTraits, CryptoTraits>
    {
        std::string m_token;
        std::string m_header_b64;
        std::string m_encrypted_key_b64;
        std::string m_iv_b64;
        std::string m_ciphertext_b64;
        std::string m_tag_b64;
        std::string m_plaintext;
        bool        m_decrypted = false;

    public:
        /// Parse a compact JWE token string.
        basic_jwe(const std::string &token, std::error_code &ec)
            : m_token(token)
        {
            // Split on '.'
            std::vector<std::string> parts;
            std::stringstream ss(token);
            std::string part;
            while (std::getline(ss, part, '.'))
                parts.push_back(part);

            if (parts.size() != 5)
            {
                ec = error::jwe_error::invalid_token;
                return;
            }

            m_header_b64        = parts[0];
            m_encrypted_key_b64 = parts[1];
            m_iv_b64            = parts[2];
            m_ciphertext_b64    = parts[3];
            m_tag_b64           = parts[4];

            // Decode and parse header JSON
            std::string header_str = CryptoTraits::base64url_decode(m_header_b64, ec);
            if (ec) { ec = error::jwe_error::invalid_base64url; return; }

            try
            {
                this->m_header = JsonTraits::parse(header_str);
            }
            catch (...)
            {
                ec = error::jwe_error::invalid_token;
            }
        }

        /// Raw compact token string.
        const std::string &get_token() const { return m_token; }

        /**
         * Decrypt the token.
         *
         * \tparam AlgType  Key management algorithm (satisfies JweAlgConcept).
         * \tparam EncType  Content encryption algorithm (satisfies JweEncConcept).
         * \param  alg      Initialized algorithm object (holds the key).
         * \param  enc      Initialized encryption object.
         * \param  ec       Set on any failure.
         */
        template <JweAlgConcept AlgType, JweEncConcept EncType>
        void decrypt(const AlgType &alg, const EncType &enc, std::error_code &ec)
        {
            // 1. Decode parts
            std::string encrypted_key = CryptoTraits::base64url_decode(m_encrypted_key_b64, ec);
            if (ec) { ec = error::jwe_error::invalid_base64url; return; }
            std::string iv = CryptoTraits::base64url_decode(m_iv_b64, ec);
            if (ec) { ec = error::jwe_error::invalid_base64url; return; }
            std::string ciphertext = CryptoTraits::base64url_decode(m_ciphertext_b64, ec);
            if (ec) { ec = error::jwe_error::invalid_base64url; return; }
            std::string tag = CryptoTraits::base64url_decode(m_tag_b64, ec);
            if (ec) { ec = error::jwe_error::invalid_base64url; return; }

            // 2. Unwrap the CEK
            std::string cek = alg.unwrap(encrypted_key, ec);
            if (ec) return;

            // 3. Decrypt content; AAD = BASE64URL(protected header)
            m_plaintext = enc.decrypt(cek, iv, m_header_b64, ciphertext, tag, ec);
            if (!ec) m_decrypted = true;
        }

        /**
         * Return the decrypted plaintext.
         * Sets ec = not_decrypted if decrypt() has not been called successfully.
         */
        const std::string &get_plaintext(std::error_code &ec) const
        {
            if (!m_decrypted)
                ec = error::jwe_error::not_decrypted;
            return m_plaintext;
        }
    };


    // ── basic_jwe_builder ─────────────────────────────────────────────────────

    /**
     * Fluent builder for creating JWE compact tokens.
     *
     * Usage:
     *   std::error_code ec;
     *   std::string token = jwe::create()
     *       .set_payload("hello world")
     *       .set_key_id("my-key")
     *       .encrypt(algorithm::A256KW("my-32-byte-kek..."),
     *                algorithm::A256GCM{}, ec);
     */
    template <jwt::JsonTraitsConcept JsonTraits, jwt::CryptoTraitsConcept CryptoTraits>
    class basic_jwe_builder
    {
        std::string m_payload;
        std::optional<std::string> m_kid;
        std::optional<std::string> m_cty;
        std::unordered_map<std::string, typename JsonTraits::value_type> m_extra_headers;

    public:
        basic_jwe_builder() = default;

        basic_jwe_builder &set_payload(const std::string &payload)
        {
            m_payload = payload;
            return *this;
        }

        basic_jwe_builder &set_key_id(const std::string &kid)
        {
            m_kid = kid;
            return *this;
        }

        basic_jwe_builder &set_content_type(const std::string &cty)
        {
            m_cty = cty;
            return *this;
        }

        basic_jwe_builder &set_header_claim(const std::string &key,
                                             typename JsonTraits::value_type val)
        {
            m_extra_headers[key] = std::move(val);
            return *this;
        }

        /**
         * Encrypt the payload and return the compact JWE token string.
         *
         * \tparam AlgType  Key management algorithm (satisfies JweAlgConcept).
         * \tparam EncType  Content encryption algorithm (satisfies JweEncConcept).
         */
        template <JweAlgConcept AlgType, JweEncConcept EncType>
        std::string encrypt(const AlgType &alg, const EncType &enc,
                            std::error_code &ec) const
        {
            // 1. Build and serialize the protected header
            auto header_obj = JsonTraits::make_empty_object();
            JsonTraits::set_key(header_obj, "alg", JsonTraits::make_string(alg.name()));
            JsonTraits::set_key(header_obj, "enc", JsonTraits::make_string(enc.name()));
            if (m_kid) JsonTraits::set_key(header_obj, "kid", JsonTraits::make_string(*m_kid));
            if (m_cty) JsonTraits::set_key(header_obj, "cty", JsonTraits::make_string(*m_cty));
            for (const auto &[k, v] : m_extra_headers)
                JsonTraits::set_key(header_obj, k, v);

            std::string header_str = JsonTraits::serialize(header_obj);
            std::string header_b64 = CryptoTraits::base64url_encode(header_str);

            // 2. Generate CEK and (possibly) encrypt it
            auto [encrypted_key, cek] = alg.wrap(enc.cek_size(), ec);
            if (ec) return "";

            // 3. Generate IV
            std::string iv = enc.generate_iv(ec);
            if (ec) return "";

            // 4. Encrypt content; AAD = BASE64URL(protected header)
            auto [ciphertext, tag] = enc.encrypt(cek, iv, header_b64, m_payload, ec);
            if (ec) return "";

            // 5. Assemble compact representation
            return header_b64                                  + "." +
                   CryptoTraits::base64url_encode(encrypted_key) + "." +
                   CryptoTraits::base64url_encode(iv)            + "." +
                   CryptoTraits::base64url_encode(ciphertext)    + "." +
                   CryptoTraits::base64url_encode(tag);
        }
    };

} // namespace jwe
