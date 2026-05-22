#pragma once

/**
 * Core header for JSON Web Key (JWK, RFC 7517).
 *
 * Provides two class templates:
 *   basic_jwk   – a single JSON Web Key (oct / RSA / EC)
 *   basic_jwks  – a JSON Web Key Set  ({"keys":[…]})
 *
 * Both are parameterised by the same JsonTraits / CryptoTraits concepts
 * already used by the jwt:: library, so they compose naturally.
 *
 * To use with the Botan + jsoncons backend, include
 *   <jwk/jwk_botan_jsoncons.hpp>
 * which provides the ready-to-use jwk::jwk / jwk::jwks aliases.
 */

#include <optional>
#include <span>
#include <memory>
#include <string>
#include <vector>

#include <jose/detail/botan_include.hpp>

#include <jose/traits/concepts.hpp>  // JsonTraitsConcept, CryptoTraitsConcept
#include <jose/jwk/jwk_error.hpp>

namespace jwk
{

// ── Key type and EC-curve enumerations ────────────────────────────────────────

enum class key_type { oct, RSA, EC };
enum class ec_curve  { P256, P384, P521 };

namespace detail
{
    inline std::string curve_to_name(ec_curve c)
    {
        switch (c)
        {
        case ec_curve::P256: return "P-256";
        case ec_curve::P384: return "P-384";
        case ec_curve::P521: return "P-521";
        }
        return "";
    }

    inline ec_curve curve_from_name(const std::string &name, std::error_code &ec)
    {
        if (name == "P-256") return ec_curve::P256;
        if (name == "P-384") return ec_curve::P384;
        if (name == "P-521") return ec_curve::P521;
        ec = error::jwk_error::unsupported_curve;
        return ec_curve::P256;
    }

    inline std::string curve_to_botan_name(ec_curve c)
    {
        switch (c)
        {
        case ec_curve::P256: return "secp256r1";
        case ec_curve::P384: return "secp384r1";
        case ec_curve::P521: return "secp521r1";
        }
        return "";
    }

    inline std::string curve_oid_to_name(const std::string &oid)
    {
        if (oid == "1.2.840.10045.3.1.7") return "P-256";
        if (oid == "1.3.132.0.34")        return "P-384";
        if (oid == "1.3.132.0.35")        return "P-521";
        return "";
    }

    // BigInt ↔ raw big-endian bytes
    inline std::string bigint_to_bytes(const Botan::BigInt &bn)
    {
        auto v = bn.serialize();
        return std::string(reinterpret_cast<const char *>(v.data()), v.size());
    }

    inline Botan::BigInt bigint_from_bytes(const std::string &s)
    {
        return Botan::BigInt(reinterpret_cast<const uint8_t *>(s.data()), s.size());
    }
} // namespace detail


// ── basic_jwk ─────────────────────────────────────────────────────────────────

template <jwt::JsonTraitsConcept JsonTraits, jwt::CryptoTraitsConcept CryptoTraits>
class basic_jwk
{
    typename JsonTraits::value_type m_json;

    // ── Internal helpers ──────────────────────────────────────────────────────

    std::string get_string_param(const std::string &key, std::error_code &ec) const
    {
        for (const auto &elem : JsonTraits::object_range(m_json))
        {
            if (JsonTraits::elem_key(elem) == key)
            {
                const auto &val = JsonTraits::elem_value(elem);
                if (!JsonTraits::is_string(val))
                {
                    ec = error::jwk_error::invalid_parameter;
                    return "";
                }
                return JsonTraits::as_string(val);
            }
        }
        ec = error::jwk_error::missing_required_parameter;
        return "";
    }

    bool has_param(const std::string &key) const
    {
        for (const auto &elem : JsonTraits::object_range(m_json))
            if (JsonTraits::elem_key(elem) == key)
                return true;
        return false;
    }

    std::string decode_b64url_param(const std::string &key, std::error_code &ec) const
    {
        std::string b64 = get_string_param(key, ec);
        if (ec) return "";
        std::string decoded = CryptoTraits::base64url_decode(b64, ec);
        if (ec) { ec = error::jwk_error::invalid_base64url; return ""; }
        return decoded;
    }

public:
    basic_jwk() : m_json(JsonTraits::make_empty_object()) {}

    explicit basic_jwk(const std::string &json_str, std::error_code &ec)
    {
        try
        {
            m_json = JsonTraits::parse(json_str);
        }
        catch (...)
        {
            ec = error::jwk_error::invalid_json;
            m_json = JsonTraits::make_empty_object();
        }
    }

    explicit basic_jwk(const typename JsonTraits::value_type &obj)
        : m_json(obj) {}

    // ── Key type ──────────────────────────────────────────────────────────────

    key_type get_key_type(std::error_code &ec) const
    {
        std::string kty = get_string_param("kty", ec);
        if (ec) return key_type::oct;
        if (kty == "oct") return key_type::oct;
        if (kty == "RSA") return key_type::RSA;
        if (kty == "EC")  return key_type::EC;
        ec = error::jwk_error::invalid_key_type;
        return key_type::oct;
    }

    // ── Common parameters ─────────────────────────────────────────────────────

    bool has_key_id()   const { return has_param("kid"); }
    bool has_algorithm()const { return has_param("alg"); }
    bool has_use()      const { return has_param("use"); }

    std::string get_key_id   (std::error_code &ec) const { return get_string_param("kid", ec); }
    std::string get_algorithm(std::error_code &ec) const { return get_string_param("alg", ec); }
    std::string get_use      (std::error_code &ec) const { return get_string_param("use", ec); }

    // ── oct parameters ────────────────────────────────────────────────────────

    bool has_k() const { return has_param("k"); }

    /// Decoded (raw) symmetric key bytes.
    std::string get_k    (std::error_code &ec) const { return decode_b64url_param("k", ec); }
    /// Raw base64url value of "k" without decoding.
    std::string get_k_b64(std::error_code &ec) const { return get_string_param("k", ec); }

    // ── RSA parameters (decoded bytes) ────────────────────────────────────────

    bool has_n()  const { return has_param("n"); }
    bool has_e()  const { return has_param("e"); }
    bool has_d()  const { return has_param("d"); }
    bool has_p()  const { return has_param("p"); }
    bool has_q()  const { return has_param("q"); }
    bool has_dp() const { return has_param("dp"); }
    bool has_dq() const { return has_param("dq"); }
    bool has_qi() const { return has_param("qi"); }

    std::string get_n (std::error_code &ec) const { return decode_b64url_param("n",  ec); }
    std::string get_e (std::error_code &ec) const { return decode_b64url_param("e",  ec); }
    std::string get_d (std::error_code &ec) const { return decode_b64url_param("d",  ec); }
    std::string get_p (std::error_code &ec) const { return decode_b64url_param("p",  ec); }
    std::string get_q (std::error_code &ec) const { return decode_b64url_param("q",  ec); }
    std::string get_dp(std::error_code &ec) const { return decode_b64url_param("dp", ec); }
    std::string get_dq(std::error_code &ec) const { return decode_b64url_param("dq", ec); }
    std::string get_qi(std::error_code &ec) const { return decode_b64url_param("qi", ec); }

    // ── EC parameters (decoded bytes) ─────────────────────────────────────────

    bool has_crv() const { return has_param("crv"); }
    bool has_x()   const { return has_param("x"); }
    bool has_y()   const { return has_param("y"); }

    ec_curve get_curve(std::error_code &ec) const
    {
        std::string crv = get_string_param("crv", ec);
        if (ec) return ec_curve::P256;
        return detail::curve_from_name(crv, ec);
    }

    std::string get_x(std::error_code &ec) const { return decode_b64url_param("x", ec); }
    std::string get_y(std::error_code &ec) const { return decode_b64url_param("y", ec); }

    // ── Serialization ──────────────────────────────────────────────────────────

    std::string to_json() const { return JsonTraits::serialize(m_json); }

    const typename JsonTraits::value_type &to_json_value() const { return m_json; }

    // ── Botan key export ──────────────────────────────────────────────────────

    /// Export as PEM-encoded SubjectPublicKeyInfo (RSA or EC).
    std::string to_pem_public(std::error_code &ec) const
    {
        try
        {
            std::error_code ec2;
            key_type kty = get_key_type(ec2);
            if (ec2) { ec = ec2; return ""; }

            if (kty == key_type::RSA)
            {
                std::string n_bytes = get_n(ec2); if (ec2) { ec = ec2; return ""; }
                std::string e_bytes = get_e(ec2); if (ec2) { ec = ec2; return ""; }
                Botan::RSA_PublicKey pub(detail::bigint_from_bytes(n_bytes),
                                        detail::bigint_from_bytes(e_bytes));
                return Botan::X509::PEM_encode(pub);
            }
            else if (kty == key_type::EC)
            {
                ec_curve crv = get_curve(ec2); if (ec2) { ec = ec2; return ""; }
                std::string x_bytes = get_x(ec2); if (ec2) { ec = ec2; return ""; }
                std::string y_bytes = get_y(ec2); if (ec2) { ec = ec2; return ""; }

                Botan::EC_Group group(detail::curve_to_botan_name(crv));

                // Uncompressed point: 0x04 || x || y
                std::vector<uint8_t> pt = {0x04};
                pt.insert(pt.end(),
                    reinterpret_cast<const uint8_t *>(x_bytes.data()),
                    reinterpret_cast<const uint8_t *>(x_bytes.data()) + x_bytes.size());
                pt.insert(pt.end(),
                    reinterpret_cast<const uint8_t *>(y_bytes.data()),
                    reinterpret_cast<const uint8_t *>(y_bytes.data()) + y_bytes.size());

                auto maybe_pt = Botan::EC_AffinePoint::deserialize(group, pt);
                if (!maybe_pt) { ec = error::jwk_error::key_export_failed; return ""; }
                Botan::ECDSA_PublicKey pub(group, *maybe_pt);
                return Botan::X509::PEM_encode(pub);
            }
            else
            {
                ec = error::jwk_error::unsupported_key_type;
                return "";
            }
        }
        catch (...)
        {
            ec = error::jwk_error::key_export_failed;
            return "";
        }
    }

    /// Export as PEM-encoded PKCS#8 private key (RSA or EC).
    /// For RSA, parameters n/e/d/p/q must all be present.
    /// For EC,  parameter d must be present.
    std::string to_pem_private(std::error_code &ec) const
    {
        try
        {
            std::error_code ec2;
            key_type kty = get_key_type(ec2);
            if (ec2) { ec = ec2; return ""; }

            Botan::AutoSeeded_RNG rng;

            if (kty == key_type::RSA)
            {
                std::string p_b = get_p(ec2); if (ec2) { ec = ec2; return ""; }
                std::string q_b = get_q(ec2); if (ec2) { ec = ec2; return ""; }
                std::string e_b = get_e(ec2); if (ec2) { ec = ec2; return ""; }
                std::string d_b = get_d(ec2); if (ec2) { ec = ec2; return ""; }

                Botan::RSA_PrivateKey priv(
                    detail::bigint_from_bytes(p_b),
                    detail::bigint_from_bytes(q_b),
                    detail::bigint_from_bytes(e_b),
                    detail::bigint_from_bytes(d_b));
                return Botan::PKCS8::PEM_encode(priv);
            }
            else if (kty == key_type::EC)
            {
                ec_curve crv = get_curve(ec2); if (ec2) { ec = ec2; return ""; }
                std::string d_b = get_d(ec2);  if (ec2) { ec = ec2; return ""; }

                Botan::EC_Group group(detail::curve_to_botan_name(crv));
                Botan::ECDSA_PrivateKey priv(rng, group, detail::bigint_from_bytes(d_b));
                return Botan::PKCS8::PEM_encode(priv);
            }
            else
            {
                ec = error::jwk_error::unsupported_key_type;
                return "";
            }
        }
        catch (...)
        {
            ec = error::jwk_error::key_export_failed;
            return "";
        }
    }

    /// Return the raw symmetric key bytes for an oct key.
    std::string to_secret(std::error_code &ec) const
    {
        std::error_code ec2;
        key_type kty = get_key_type(ec2);
        if (ec2) { ec = ec2; return ""; }
        if (kty != key_type::oct)
        {
            ec = error::jwk_error::unsupported_key_type;
            return "";
        }
        return get_k(ec);
    }

    // ── Static constructors ───────────────────────────────────────────────────

    /// Build a JWK from a PEM-encoded SubjectPublicKeyInfo (RSA or EC).
    static basic_jwk from_pem_public(const std::string &pem,
                                     std::error_code &ec,
                                     const std::optional<std::string> &kid = std::nullopt)
    {
        try
        {
            auto key_bytes = std::vector<uint8_t>(pem.begin(), pem.end());
            auto pub_key   = Botan::X509::load_key(key_bytes);
            auto obj       = JsonTraits::make_empty_object();

            auto set_bn = [&](const std::string &k, const Botan::BigInt &bn) {
                JsonTraits::set_key(obj, k,
                    JsonTraits::make_string(
                        CryptoTraits::base64url_encode(detail::bigint_to_bytes(bn))));
            };

            if (pub_key->algo_name() == "RSA")
            {
                const auto *rsa = dynamic_cast<const Botan::RSA_PublicKey *>(pub_key.get());
                JsonTraits::set_key(obj, "kty", JsonTraits::make_string("RSA"));
                set_bn("n", rsa->get_n());
                set_bn("e", rsa->get_e());
            }
            else if (pub_key->algo_name() == "ECDSA")
            {
                const auto *ecdsa = dynamic_cast<const Botan::ECDSA_PublicKey *>(pub_key.get());
                std::string crv = detail::curve_oid_to_name(
                    ecdsa->domain().get_curve_oid().to_string());
                if (crv.empty()) { ec = error::jwk_error::unsupported_curve; return basic_jwk{}; }

                JsonTraits::set_key(obj, "kty", JsonTraits::make_string("EC"));
                JsonTraits::set_key(obj, "crv", JsonTraits::make_string(crv));
                auto set_ec_bytes = [&](const std::string &k, std::vector<uint8_t> bytes) {
                    JsonTraits::set_key(obj, k, JsonTraits::make_string(
                        CryptoTraits::base64url_encode(
                            std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size()))));
                };
                auto raw_pt   = ecdsa->raw_public_key_bits();
                auto maybe_pt = Botan::EC_AffinePoint::deserialize(ecdsa->domain(), raw_pt);
                if (!maybe_pt) { ec = error::jwk_error::key_import_failed; return basic_jwk{}; }
                set_ec_bytes("x", maybe_pt->x_bytes<std::vector<uint8_t>>());
                set_ec_bytes("y", maybe_pt->y_bytes<std::vector<uint8_t>>());
            }
            else
            {
                ec = error::jwk_error::unsupported_key_type;
                return basic_jwk{};
            }

            if (kid) JsonTraits::set_key(obj, "kid", JsonTraits::make_string(*kid));
            return basic_jwk(obj);
        }
        catch (...)
        {
            ec = error::jwk_error::key_import_failed;
            return basic_jwk{};
        }
    }

    /// Build a JWK from a PEM-encoded PKCS#8 private key (RSA or EC).
    static basic_jwk from_pem_private(const std::string &pem,
                                      std::error_code &ec,
                                      const std::optional<std::string> &kid = std::nullopt,
                                      const std::string &password = "")
    {
        try
        {
            auto key_span = std::span<const uint8_t>(
                reinterpret_cast<const uint8_t *>(pem.data()), pem.size());

            std::unique_ptr<Botan::Private_Key> priv_key;
            if (password.empty())
                priv_key = Botan::PKCS8::load_key(key_span);
            else
                priv_key = Botan::PKCS8::load_key(key_span, password);

            auto obj = JsonTraits::make_empty_object();

            auto set_bn = [&](const std::string &k, const Botan::BigInt &bn) {
                JsonTraits::set_key(obj, k,
                    JsonTraits::make_string(
                        CryptoTraits::base64url_encode(detail::bigint_to_bytes(bn))));
            };

            if (priv_key->algo_name() == "RSA")
            {
                const auto *rsa = dynamic_cast<const Botan::RSA_PrivateKey *>(priv_key.get());
                JsonTraits::set_key(obj, "kty", JsonTraits::make_string("RSA"));
                set_bn("n",  rsa->get_n());
                set_bn("e",  rsa->get_e());
                set_bn("d",  rsa->get_d());
                set_bn("p",  rsa->get_p());
                set_bn("q",  rsa->get_q());
                set_bn("dp", rsa->get_d1());   // d mod (p-1)
                set_bn("dq", rsa->get_d2());   // d mod (q-1)
                set_bn("qi", rsa->get_c());    // q^{-1} mod p
            }
            else if (priv_key->algo_name() == "ECDSA")
            {
                const auto *ecdsa = dynamic_cast<const Botan::ECDSA_PrivateKey *>(priv_key.get());
                std::string crv = detail::curve_oid_to_name(
                    ecdsa->domain().get_curve_oid().to_string());
                if (crv.empty()) { ec = error::jwk_error::unsupported_curve; return basic_jwk{}; }

                JsonTraits::set_key(obj, "kty", JsonTraits::make_string("EC"));
                JsonTraits::set_key(obj, "crv", JsonTraits::make_string(crv));
                auto set_ec_bytes = [&](const std::string &k, std::vector<uint8_t> bytes) {
                    JsonTraits::set_key(obj, k, JsonTraits::make_string(
                        CryptoTraits::base64url_encode(
                            std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size()))));
                };
                auto raw_pt   = ecdsa->raw_public_key_bits();
                auto maybe_pt = Botan::EC_AffinePoint::deserialize(ecdsa->domain(), raw_pt);
                if (!maybe_pt) { ec = error::jwk_error::key_import_failed; return basic_jwk{}; }
                set_ec_bytes("x", maybe_pt->x_bytes<std::vector<uint8_t>>());
                set_ec_bytes("y", maybe_pt->y_bytes<std::vector<uint8_t>>());
                set_bn("d", ecdsa->private_value());
            }
            else
            {
                ec = error::jwk_error::unsupported_key_type;
                return basic_jwk{};
            }

            if (kid) JsonTraits::set_key(obj, "kid", JsonTraits::make_string(*kid));
            return basic_jwk(obj);
        }
        catch (...)
        {
            ec = error::jwk_error::key_import_failed;
            return basic_jwk{};
        }
    }

    /// Build an oct JWK from raw key bytes.
    static basic_jwk from_secret(const std::string &key_bytes,
                                  std::error_code & /*ec*/,
                                  const std::optional<std::string> &kid = std::nullopt,
                                  const std::optional<std::string> &alg = std::nullopt)
    {
        auto obj = JsonTraits::make_empty_object();
        JsonTraits::set_key(obj, "kty", JsonTraits::make_string("oct"));
        JsonTraits::set_key(obj, "k",
            JsonTraits::make_string(CryptoTraits::base64url_encode(key_bytes)));
        if (kid) JsonTraits::set_key(obj, "kid", JsonTraits::make_string(*kid));
        if (alg) JsonTraits::set_key(obj, "alg", JsonTraits::make_string(*alg));
        return basic_jwk(obj);
    }
};


// ── basic_jwks ────────────────────────────────────────────────────────────────

/**
 * A JSON Web Key Set: {"keys":[<jwk>, …]}.
 */
template <jwt::JsonTraitsConcept JsonTraits, jwt::CryptoTraitsConcept CryptoTraits>
class basic_jwks
{
    std::vector<basic_jwk<JsonTraits, CryptoTraits>> m_keys;

public:
    basic_jwks() = default;

    /// Parse a compact JWKS JSON string.
    explicit basic_jwks(const std::string &json_str, std::error_code &ec)
    {
        try
        {
            auto root = JsonTraits::parse(json_str);
            for (const auto &elem : JsonTraits::object_range(root))
            {
                if (JsonTraits::elem_key(elem) != "keys") continue;

                const auto &arr = JsonTraits::elem_value(elem);
                if (!JsonTraits::is_array(arr))
                {
                    ec = error::jwk_error::invalid_json;
                    return;
                }
                for (const auto &key_elem : JsonTraits::array_range(arr))
                    m_keys.emplace_back(key_elem);
                break;
            }
        }
        catch (...)
        {
            ec = error::jwk_error::invalid_json;
        }
    }

    void add_key(basic_jwk<JsonTraits, CryptoTraits> key)
    {
        m_keys.push_back(std::move(key));
    }

    const std::vector<basic_jwk<JsonTraits, CryptoTraits>> &get_keys() const
    {
        return m_keys;
    }

    std::optional<basic_jwk<JsonTraits, CryptoTraits>>
    find_by_kid(const std::string &kid) const
    {
        for (const auto &key : m_keys)
        {
            if (!key.has_key_id()) continue;
            std::error_code ec;
            if (key.get_key_id(ec) == kid && !ec)
                return key;
        }
        return std::nullopt;
    }

    std::string to_json() const
    {
        std::string result = R"({"keys":[)";
        for (size_t i = 0; i < m_keys.size(); ++i)
        {
            if (i > 0) result += ',';
            result += m_keys[i].to_json();
        }
        result += "]}";
        return result;
    }
};

} // namespace jwk
