#pragma once

/**
 * Core header for JSON Web Signature (JWS, RFC 7515) – compact serialization.
 *
 * JWS is the low-level signing layer that JWT builds on.  The key difference
 * from JWT is that the JWS payload is arbitrary bytes, not a JSON claims set.
 * The same algorithm implementations (HS256, RS256, ES256, …) from the jwt
 * library are reused directly.
 *
 * Compact format:
 *   BASE64URL(JWS Protected Header) . BASE64URL(Payload) . BASE64URL(Signature)
 *
 * The signing input is the ASCII string:
 *   BASE64URL(header) || "." || BASE64URL(payload)
 *
 * Classes:
 *   basic_jws          – parsed token (header claims + raw payload + signature)
 *   basic_jws_builder  – fluent builder; produces a signed compact token
 *   basic_jws_verifier – verifies the signature of a basic_jws token
 *
 * Both builder and verifier are parameterised over jwt::AlgorithmConcept, so
 * any jwt::algorithm::hs256 / rs256 / es256 / … object works without change.
 *
 * For the ready-to-use aliases and free functions include:
 *   <jws/jws_botan_jsoncons.hpp>
 */

#include <memory>
#include <string>
#include <unordered_map>

#include <jose/jwt/jwt.hpp>       // JsonTraitsConcept, CryptoTraitsConcept,
                                  // AlgorithmConcept, basic_claim, basic_header
#include <jose/jws/jws_error.hpp>

namespace jws
{

    // ── basic_jws ─────────────────────────────────────────────────────────────

    /**
     * A parsed JWS compact token.
     *
     * Inherits jwt::basic_header<JsonTraits>, so the full set of typed header
     * accessors (get_algorithm, get_type, get_key_id, get_header_claim, …)
     * is available without any duplication.
     *
     * The payload is stored as raw (decoded) bytes and exposed as-is.
     */
    template <jwt::JsonTraitsConcept JsonTraits, jwt::CryptoTraitsConcept CryptoTraits>
    class basic_jws : public jwt::basic_header<JsonTraits>
    {
        std::string m_token;
        std::string m_header_b64;
        std::string m_payload_b64;
        std::string m_sig_b64;
        std::string m_payload;    ///< Base64url-decoded payload bytes
        std::string m_signature;  ///< Base64url-decoded raw signature

    public:
        /**
         * Parse a compact JWS token.
         *
         * On success the header claims map is populated and the payload /
         * signature are decoded.  Sets ec on any parsing failure.
         */
        basic_jws(const std::string &token, std::error_code &ec)
            : m_token(token)
        {
            auto hdr_end = token.find('.');
            if (hdr_end == std::string::npos)
            {
                ec = error::jws_error::invalid_token;
                return;
            }
            auto payload_end = token.find('.', hdr_end + 1);
            if (payload_end == std::string::npos)
            {
                ec = error::jws_error::invalid_token;
                return;
            }

            m_header_b64  = token.substr(0, hdr_end);
            m_payload_b64 = token.substr(hdr_end + 1, payload_end - hdr_end - 1);
            m_sig_b64     = token.substr(payload_end + 1);

            // Decode all three parts
            std::error_code ec1, ec2, ec3;
            std::string header_str = CryptoTraits::base64url_decode(m_header_b64, ec1);
            m_payload              = CryptoTraits::base64url_decode(m_payload_b64, ec2);
            m_signature            = CryptoTraits::base64url_decode(m_sig_b64,     ec3);

            if (ec1 || ec2 || ec3)
            {
                ec = error::jws_error::invalid_base64url;
                return;
            }

            // Populate header_claims (inherited from basic_header<JsonTraits>)
            try
            {
                auto val = JsonTraits::parse(header_str);
                for (const auto &e : JsonTraits::object_range(val))
                {
                    this->header_claims[JsonTraits::elem_key(e)] =
                        jwt::basic_claim<JsonTraits>(JsonTraits::elem_value(e));
                }
            }
            catch (...)
            {
                ec = error::jws_error::invalid_token;
            }
        }

        // ── Raw token parts ───────────────────────────────────────────────────

        /// Full compact token string as passed to the constructor.
        const std::string &get_token()         const { return m_token;     }
        /// Base64url-encoded header (used as signing input prefix).
        const std::string &get_header_base64() const { return m_header_b64; }
        /// Base64url-encoded payload.
        const std::string &get_payload_base64()const { return m_payload_b64; }
        /// Base64url-encoded signature.
        const std::string &get_signature_base64() const { return m_sig_b64; }

        // ── Decoded parts ─────────────────────────────────────────────────────

        /// Decoded payload bytes (arbitrary content – not parsed as JSON).
        const std::string &get_payload()   const { return m_payload;   }
        /// Decoded raw signature bytes.
        const std::string &get_signature() const { return m_signature; }
    };


    // ── basic_jws_builder ─────────────────────────────────────────────────────

    /**
     * Fluent builder for creating JWS compact tokens.
     *
     * Usage:
     *   std::error_code ec;
     *   std::string token = jws::create()
     *       .set_payload("hello world")
     *       .set_type("JOSE")
     *       .set_key_id("my-key")
     *       .sign(jwt::algorithm::hs256("secret"), ec);
     */
    template <jwt::JsonTraitsConcept JsonTraits, jwt::CryptoTraitsConcept CryptoTraits>
    class basic_jws_builder
    {
        std::string m_payload;
        std::unordered_map<std::string, jwt::basic_claim<JsonTraits>> m_header_claims;

    public:
        basic_jws_builder() = default;

        /// Set the raw payload bytes (any content – not necessarily JSON).
        basic_jws_builder &set_payload(const std::string &payload)
        {
            m_payload = payload;
            return *this;
        }

        /// Set a header claim.
        basic_jws_builder &set_header_claim(const std::string &id,
                                            jwt::basic_claim<JsonTraits> c)
        {
            m_header_claims[id] = std::move(c);
            return *this;
        }

        /// Set the "typ" header claim.
        basic_jws_builder &set_type(const std::string &str)
        {
            return set_header_claim("typ", jwt::basic_claim<JsonTraits>(str));
        }

        /// Set the "cty" header claim.
        basic_jws_builder &set_content_type(const std::string &str)
        {
            return set_header_claim("cty", jwt::basic_claim<JsonTraits>(str));
        }

        /// Set the "kid" header claim.
        basic_jws_builder &set_key_id(const std::string &str)
        {
            return set_header_claim("kid", jwt::basic_claim<JsonTraits>(str));
        }

        /**
         * Sign the payload and return the compact JWS token string.
         *
         * The "alg" header claim is set automatically from algo.name().
         *
         * \tparam T  Algorithm type satisfying jwt::AlgorithmConcept.
         * \param  algo  Initialized algorithm object.
         * \param  ec    Set on any failure.
         */
        template <jwt::AlgorithmConcept T>
        std::string sign(const T &algo, std::error_code &ec)
        {
            // Inject "alg" from the algorithm object
            m_header_claims["alg"] = jwt::basic_claim<JsonTraits>(algo.name());

            // Serialize header
            auto header_obj = JsonTraits::make_empty_object();
            for (const auto &[k, v] : m_header_claims)
                JsonTraits::set_key(header_obj, k, v.to_json());

            std::string header_b64  = CryptoTraits::base64url_encode(
                                          JsonTraits::serialize(header_obj));
            std::string payload_b64 = CryptoTraits::base64url_encode(m_payload);
            std::string signing_input = header_b64 + "." + payload_b64;

            std::string sig = algo.sign(signing_input, ec);
            if (ec) return "";

            return signing_input + "." + CryptoTraits::base64url_encode(sig);
        }
    };


    // ── basic_jws_verifier ────────────────────────────────────────────────────

    /**
     * Verifier for JWS compact tokens.
     *
     * Registers one or more allowed algorithms; verifies that the token's
     * "alg" header matches and that the signature is valid.
     *
     * Usage:
     *   std::error_code ec;
     *   jws::verify()
     *       .allow_algorithm(jwt::algorithm::hs256("secret"))
     *       .verify(decoded_token, ec);
     */
    template <jwt::JsonTraitsConcept JsonTraits, jwt::CryptoTraitsConcept CryptoTraits>
    class basic_jws_verifier
    {
        // Type-erased algorithm storage – same pattern as jwt::basic_verifier
        struct algo_base
        {
            virtual ~algo_base() = default;
            virtual void verify(const std::string &data,
                                const std::string &sig,
                                std::error_code   &ec) = 0;
        };

        template <typename T>
        struct algo_impl : public algo_base
        {
            T alg;
            explicit algo_impl(T a) : alg(std::move(a)) {}
            void verify(const std::string &data,
                        const std::string &sig,
                        std::error_code   &ec) override
            {
                alg.verify(data, sig, ec);
            }
        };

        std::unordered_map<std::string, std::shared_ptr<algo_base>> m_algs;

    public:
        basic_jws_verifier() = default;

        /**
         * Register an algorithm that is acceptable for verification.
         * \tparam T  Algorithm type satisfying jwt::AlgorithmConcept.
         */
        template <jwt::AlgorithmConcept T>
        basic_jws_verifier &allow_algorithm(T alg)
        {
            m_algs[alg.name()] = std::make_shared<algo_impl<T>>(std::move(alg));
            return *this;
        }

        /**
         * Verify the signature of a decoded JWS token.
         *
         * Sets ec on:
         *   - jws_error::unknown_algorithm  if the token's "alg" is not registered
         *   - signature_verification_error::invalid_signature  on bad signature
         *   - jws_error::invalid_base64url  if header/payload decoding fails
         */
        void verify(const basic_jws<JsonTraits, CryptoTraits> &token,
                    std::error_code &ec) const
        {
            // Look up the algorithm declared in the header
            std::error_code ec2;
            std::string alg_name = token.get_algorithm(ec2);
            if (ec2) { ec = ec2; return; }

            auto it = m_algs.find(alg_name);
            if (it == m_algs.end())
            {
                ec = error::jws_error::unknown_algorithm;
                return;
            }

            // Signing input = header_b64 || "." || payload_b64
            const std::string data = token.get_header_base64() + "." +
                                     token.get_payload_base64();
            const std::string &sig = token.get_signature();

            it->second->verify(data, sig, ec);
        }
    };

} // namespace jws
