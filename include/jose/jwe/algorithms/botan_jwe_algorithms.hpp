#pragma once

/**
 * Botan-backed implementations of JweAlgConcept and JweEncConcept.
 *
 * Key management algorithms (alg):
 *   dir          – Direct symmetric-key encryption (no key wrapping)
 *   RSA_OAEP     – RSAES-OAEP with SHA-1  (RFC 7518 "RSA-OAEP")
 *   RSA_OAEP_256 – RSAES-OAEP with SHA-256 (RFC 7518 "RSA-OAEP-256")
 *   A128KW       – AES-128 Key Wrap (RFC 3394)
 *   A192KW       – AES-192 Key Wrap
 *   A256KW       – AES-256 Key Wrap
 *   A128GCMKW    – AES-128-GCM Key Wrap
 *   A192GCMKW    – AES-192-GCM Key Wrap
 *   A256GCMKW    – AES-256-GCM Key Wrap
 *
 * Content encryption algorithms (enc):
 *   A128GCM      – AES-128-GCM
 *   A192GCM      – AES-192-GCM
 *   A256GCM      – AES-256-GCM
 *   A128CBC_HS256 – AES-128-CBC + HMAC-SHA-256
 *   A192CBC_HS384 – AES-192-CBC + HMAC-SHA-384
 *   A256CBC_HS512 – AES-256-CBC + HMAC-SHA-512
 */

#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <jose/detail/botan_include.hpp>

#include <jose/jwe/jwe_error.hpp>

namespace jwe
{
namespace algorithm
{

    // =========================================================================
    // Key management algorithms
    // =========================================================================

    // ── dir ──────────────────────────────────────────────────────────────────

    /**
     * Direct Encryption (RFC 7518 §4.5).
     * The provided key IS the Content Encryption Key – no wrapping is done.
     */
    struct dir
    {
        explicit dir(std::string key) : m_key(std::move(key)) {}

        /// Returns {"", direct_key}.
        std::pair<std::string, std::string>
        wrap(size_t /*cek_size*/, std::error_code & /*ec*/) const
        {
            return {"", m_key};
        }

        /// Returns the stored direct key regardless of encrypted_key.
        std::string unwrap(const std::string & /*encrypted_key*/,
                           std::error_code & /*ec*/) const
        {
            return m_key;
        }

        std::string name() const { return "dir"; }

    private:
        std::string m_key;
    };


    // ── RSA-OAEP base ─────────────────────────────────────────────────────────

    struct rsa_oaep_base
    {
        rsa_oaep_base(std::string pub_pem, std::string priv_pem,
                      std::string padding, std::string alg_name)
            : m_pub(std::move(pub_pem)), m_priv(std::move(priv_pem)),
              m_padding(std::move(padding)), m_name(std::move(alg_name)) {}

        /// Generates a random CEK of `cek_size` bytes, encrypts with RSA-OAEP.
        std::pair<std::string, std::string>
        wrap(size_t cek_size, std::error_code &ec) const
        {
            try
            {
                Botan::AutoSeeded_RNG rng;
                std::vector<uint8_t> cek(cek_size);
                rng.randomize(cek.data(), cek.size());

                auto key_bytes = std::vector<uint8_t>(m_pub.begin(), m_pub.end());
                auto pub_key   = Botan::X509::load_key(key_bytes);

                Botan::PK_Encryptor_EME enc(*pub_key, rng, m_padding);
                auto wrapped = enc.encrypt(cek.data(), cek.size(), rng);

                std::string wrapped_str(reinterpret_cast<const char *>(wrapped.data()),
                                        wrapped.size());
                std::string cek_str(reinterpret_cast<const char *>(cek.data()), cek.size());
                return {wrapped_str, cek_str};
            }
            catch (...)
            {
                ec = error::jwe_error::key_wrap_failed;
                return {"", ""};
            }
        }

        /// Decrypts the wrapped CEK with the RSA private key.
        std::string unwrap(const std::string &encrypted_key, std::error_code &ec) const
        {
            try
            {
                auto key_span = std::span<const uint8_t>(
                    reinterpret_cast<const uint8_t *>(m_priv.data()), m_priv.size());
                Botan::AutoSeeded_RNG rng;
                auto priv_key = Botan::PKCS8::load_key(key_span);

                Botan::PK_Decryptor_EME dec(*priv_key, rng, m_padding);
                auto cek = dec.decrypt(
                    reinterpret_cast<const uint8_t *>(encrypted_key.data()),
                    encrypted_key.size());

                return std::string(cek.begin(), cek.end());
            }
            catch (...)
            {
                ec = error::jwe_error::key_unwrap_failed;
                return "";
            }
        }

        std::string name() const { return m_name; }

    private:
        std::string m_pub, m_priv, m_padding, m_name;
    };

    struct RSA_OAEP : public rsa_oaep_base
    {
        RSA_OAEP(const std::string &pub = "", const std::string &priv = "")
            : rsa_oaep_base(pub, priv, "OAEP(SHA-1)", "RSA-OAEP") {}
    };

    struct RSA_OAEP_256 : public rsa_oaep_base
    {
        RSA_OAEP_256(const std::string &pub = "", const std::string &priv = "")
            : rsa_oaep_base(pub, priv, "OAEP(SHA-256)", "RSA-OAEP-256") {}
    };


    // ── AES Key Wrap (RFC 3394) ───────────────────────────────────────────────

    struct aes_kw_base
    {
        aes_kw_base(std::string kek, std::string alg_name)
            : m_kek(std::move(kek)), m_name(std::move(alg_name)) {}

        /// Generates a random CEK, wraps it with RFC 3394 AES Key Wrap.
        std::pair<std::string, std::string>
        wrap(size_t cek_size, std::error_code &ec) const
        {
            try
            {
                Botan::AutoSeeded_RNG rng;
                Botan::secure_vector<uint8_t> cek(cek_size);
                rng.randomize(cek.data(), cek.size());

                Botan::SymmetricKey kek(
                    reinterpret_cast<const uint8_t *>(m_kek.data()), m_kek.size());
                auto wrapped = Botan::rfc3394_keywrap(cek, kek);

                std::string wrapped_str(reinterpret_cast<const char *>(wrapped.data()),
                                        wrapped.size());
                std::string cek_str(reinterpret_cast<const char *>(cek.data()), cek.size());
                return {wrapped_str, cek_str};
            }
            catch (...)
            {
                ec = error::jwe_error::key_wrap_failed;
                return {"", ""};
            }
        }

        /// Unwraps the CEK with RFC 3394 AES Key Unwrap.
        std::string unwrap(const std::string &wrapped_key, std::error_code &ec) const
        {
            try
            {
                Botan::SymmetricKey kek(
                    reinterpret_cast<const uint8_t *>(m_kek.data()), m_kek.size());
                Botan::secure_vector<uint8_t> wrapped(
                    reinterpret_cast<const uint8_t *>(wrapped_key.data()),
                    reinterpret_cast<const uint8_t *>(wrapped_key.data()) + wrapped_key.size());
                auto cek = Botan::rfc3394_keyunwrap(wrapped, kek);
                return std::string(reinterpret_cast<const char *>(cek.data()), cek.size());
            }
            catch (...)
            {
                ec = error::jwe_error::key_unwrap_failed;
                return "";
            }
        }

        std::string name() const { return m_name; }

    private:
        std::string m_kek, m_name;
    };

    struct A128KW : public aes_kw_base { explicit A128KW(std::string kek) : aes_kw_base(std::move(kek), "A128KW") {} };
    struct A192KW : public aes_kw_base { explicit A192KW(std::string kek) : aes_kw_base(std::move(kek), "A192KW") {} };
    struct A256KW : public aes_kw_base { explicit A256KW(std::string kek) : aes_kw_base(std::move(kek), "A256KW") {} };


    // ── AES-GCM Key Wrap ──────────────────────────────────────────────────────
    //
    // Encrypted key format (not a JWE standard field): IV(12) || CT+TAG(cek+16)
    // This is a compact internal format; the JWE "encrypted_key" field holds it.

    struct aes_gcm_kw_base
    {
        aes_gcm_kw_base(std::string kek, std::string alg_name, int key_bits)
            : m_kek(std::move(kek)), m_name(std::move(alg_name)), m_key_bits(key_bits) {}

        std::pair<std::string, std::string>
        wrap(size_t cek_size, std::error_code &ec) const
        {
            try
            {
                Botan::AutoSeeded_RNG rng;
                std::vector<uint8_t> cek(cek_size);
                rng.randomize(cek.data(), cek.size());

                std::vector<uint8_t> iv(12);
                rng.randomize(iv.data(), iv.size());

                std::string cipher_name = "AES-" + std::to_string(m_key_bits) + "/GCM";
                auto aead = Botan::AEAD_Mode::create_or_throw(cipher_name,
                                                              Botan::Cipher_Dir::Encryption);
                aead->set_key(
                    reinterpret_cast<const uint8_t *>(m_kek.data()), m_kek.size());
                aead->start(iv.data(), iv.size());

                Botan::secure_vector<uint8_t> buf(cek.begin(), cek.end());
                aead->finish(buf); // buf = CT(cek_size) + TAG(16)

                // Prepend IV: IV(12) || CT+TAG
                std::string result;
                result.append(reinterpret_cast<const char *>(iv.data()), iv.size());
                result.append(reinterpret_cast<const char *>(buf.data()), buf.size());

                std::string cek_str(reinterpret_cast<const char *>(cek.data()), cek.size());
                return {result, cek_str};
            }
            catch (...)
            {
                ec = error::jwe_error::key_wrap_failed;
                return {"", ""};
            }
        }

        std::string unwrap(const std::string &wrapped_key, std::error_code &ec) const
        {
            const size_t iv_len  = 12;
            const size_t tag_len = 16;
            if (wrapped_key.size() < iv_len + tag_len)
            {
                ec = error::jwe_error::key_unwrap_failed;
                return "";
            }
            try
            {
                const auto *data = reinterpret_cast<const uint8_t *>(wrapped_key.data());

                std::string cipher_name = "AES-" + std::to_string(m_key_bits) + "/GCM";
                auto aead = Botan::AEAD_Mode::create_or_throw(cipher_name,
                                                              Botan::Cipher_Dir::Decryption);
                aead->set_key(
                    reinterpret_cast<const uint8_t *>(m_kek.data()), m_kek.size());
                aead->start(data, iv_len);

                Botan::secure_vector<uint8_t> buf(data + iv_len,
                                                  data + wrapped_key.size());
                aead->finish(buf);
                return std::string(reinterpret_cast<const char *>(buf.data()), buf.size());
            }
            catch (...)
            {
                ec = error::jwe_error::key_unwrap_failed;
                return "";
            }
        }

        std::string name() const { return m_name; }

    private:
        std::string m_kek, m_name;
        int m_key_bits;
    };

    struct A128GCMKW : public aes_gcm_kw_base { explicit A128GCMKW(std::string kek) : aes_gcm_kw_base(std::move(kek), "A128GCMKW", 128) {} };
    struct A192GCMKW : public aes_gcm_kw_base { explicit A192GCMKW(std::string kek) : aes_gcm_kw_base(std::move(kek), "A192GCMKW", 192) {} };
    struct A256GCMKW : public aes_gcm_kw_base { explicit A256GCMKW(std::string kek) : aes_gcm_kw_base(std::move(kek), "A256GCMKW", 256) {} };


    // =========================================================================
    // Content encryption algorithms
    // =========================================================================

    // ── AES-GCM ───────────────────────────────────────────────────────────────

    struct aes_gcm_base
    {
        aes_gcm_base(std::string alg_name, int key_bits, size_t cek_bytes)
            : m_name(std::move(alg_name)), m_key_bits(key_bits), m_cek_size(cek_bytes) {}

        /// Returns {ciphertext, auth_tag}.
        std::pair<std::string, std::string>
        encrypt(const std::string &cek, const std::string &iv,
                const std::string &aad, const std::string &plaintext,
                std::error_code &ec) const
        {
            try
            {
                std::string cipher_name = "AES-" + std::to_string(m_key_bits) + "/GCM";
                auto aead = Botan::AEAD_Mode::create_or_throw(cipher_name,
                                                              Botan::Cipher_Dir::Encryption);
                aead->set_key(
                    reinterpret_cast<const uint8_t *>(cek.data()), cek.size());
                aead->set_associated_data(
                    reinterpret_cast<const uint8_t *>(aad.data()), aad.size());
                aead->start(
                    reinterpret_cast<const uint8_t *>(iv.data()), iv.size());

                Botan::secure_vector<uint8_t> buf(plaintext.begin(), plaintext.end());
                aead->finish(buf); // buf = CT || TAG(16)

                const size_t tag_len = 16;
                const size_t ct_len  = buf.size() - tag_len;
                std::string ct (reinterpret_cast<const char *>(buf.data()), ct_len);
                std::string tag(reinterpret_cast<const char *>(buf.data() + ct_len), tag_len);
                return {ct, tag};
            }
            catch (...)
            {
                ec = error::jwe_error::encryption_failed;
                return {"", ""};
            }
        }

        std::string decrypt(const std::string &cek, const std::string &iv,
                            const std::string &aad, const std::string &ciphertext,
                            const std::string &tag, std::error_code &ec) const
        {
            try
            {
                std::string cipher_name = "AES-" + std::to_string(m_key_bits) + "/GCM";
                auto aead = Botan::AEAD_Mode::create_or_throw(cipher_name,
                                                              Botan::Cipher_Dir::Decryption);
                aead->set_key(
                    reinterpret_cast<const uint8_t *>(cek.data()), cek.size());
                aead->set_associated_data(
                    reinterpret_cast<const uint8_t *>(aad.data()), aad.size());
                aead->start(
                    reinterpret_cast<const uint8_t *>(iv.data()), iv.size());

                // GCM decryption expects CT || TAG together
                Botan::secure_vector<uint8_t> buf;
                buf.insert(buf.end(),
                    reinterpret_cast<const uint8_t *>(ciphertext.data()),
                    reinterpret_cast<const uint8_t *>(ciphertext.data()) + ciphertext.size());
                buf.insert(buf.end(),
                    reinterpret_cast<const uint8_t *>(tag.data()),
                    reinterpret_cast<const uint8_t *>(tag.data()) + tag.size());
                aead->finish(buf); // throws on auth failure
                return std::string(reinterpret_cast<const char *>(buf.data()), buf.size());
            }
            catch (...)
            {
                ec = error::jwe_error::decryption_failed;
                return "";
            }
        }

        /// Generate a random 96-bit (12-byte) IV for GCM.
        std::string generate_iv(std::error_code & /*ec*/) const
        {
            Botan::AutoSeeded_RNG rng;
            std::vector<uint8_t> iv(12);
            rng.randomize(iv.data(), iv.size());
            return std::string(reinterpret_cast<const char *>(iv.data()), iv.size());
        }

        size_t      cek_size() const { return m_cek_size; }
        std::string name()     const { return m_name; }

    private:
        std::string m_name;
        int         m_key_bits;
        size_t      m_cek_size;
    };

    struct A128GCM : public aes_gcm_base { A128GCM() : aes_gcm_base("A128GCM", 128, 16) {} };
    struct A192GCM : public aes_gcm_base { A192GCM() : aes_gcm_base("A192GCM", 192, 24) {} };
    struct A256GCM : public aes_gcm_base { A256GCM() : aes_gcm_base("A256GCM", 256, 32) {} };


    // ── AES-CBC + HMAC (RFC 7518 §5.2) ───────────────────────────────────────
    //
    // CEK layout: MAC_KEY (half) || ENC_KEY (half)
    // Tag        = T[0 : tag_size], where T = HMAC(MAC_KEY, AAD||IV||CT||AL)
    //   AL = len(AAD) in bits as 64-bit big-endian

    struct aes_cbc_hs_base
    {
        aes_cbc_hs_base(std::string alg_name, int aes_bits, int hmac_bits, size_t cek_bytes)
            : m_name(std::move(alg_name)), m_aes_bits(aes_bits),
              m_hmac_bits(hmac_bits), m_cek_size(cek_bytes) {}

        std::pair<std::string, std::string>
        encrypt(const std::string &cek, const std::string &iv,
                const std::string &aad, const std::string &plaintext,
                std::error_code &ec) const
        {
            try
            {
                auto [mac_key, enc_key] = split_cek(cek);

                // AES-CBC encryption
                std::string cipher_name = "AES-" + std::to_string(m_aes_bits) + "/CBC/PKCS7";
                auto cipher = Botan::Cipher_Mode::create_or_throw(cipher_name,
                                                                   Botan::Cipher_Dir::Encryption);
                cipher->set_key(
                    reinterpret_cast<const uint8_t *>(enc_key.data()), enc_key.size());
                cipher->start(
                    reinterpret_cast<const uint8_t *>(iv.data()), iv.size());

                Botan::secure_vector<uint8_t> buf(plaintext.begin(), plaintext.end());
                cipher->finish(buf);
                std::string ciphertext(reinterpret_cast<const char *>(buf.data()), buf.size());

                std::string tag = compute_tag(mac_key, aad, iv, ciphertext, ec);
                if (ec) return {"", ""};
                return {ciphertext, tag};
            }
            catch (...)
            {
                ec = error::jwe_error::encryption_failed;
                return {"", ""};
            }
        }

        std::string decrypt(const std::string &cek, const std::string &iv,
                            const std::string &aad, const std::string &ciphertext,
                            const std::string &tag, std::error_code &ec) const
        {
            try
            {
                auto [mac_key, enc_key] = split_cek(cek);

                // Verify authentication tag before decryption
                std::string expected = compute_tag(mac_key, aad, iv, ciphertext, ec);
                if (ec) return "";
                if (tag != expected)
                {
                    ec = error::jwe_error::invalid_ciphertext;
                    return "";
                }

                // AES-CBC decryption
                std::string cipher_name = "AES-" + std::to_string(m_aes_bits) + "/CBC/PKCS7";
                auto cipher = Botan::Cipher_Mode::create_or_throw(cipher_name,
                                                                   Botan::Cipher_Dir::Decryption);
                cipher->set_key(
                    reinterpret_cast<const uint8_t *>(enc_key.data()), enc_key.size());
                cipher->start(
                    reinterpret_cast<const uint8_t *>(iv.data()), iv.size());

                Botan::secure_vector<uint8_t> buf(
                    reinterpret_cast<const uint8_t *>(ciphertext.data()),
                    reinterpret_cast<const uint8_t *>(ciphertext.data()) + ciphertext.size());
                cipher->finish(buf);
                return std::string(reinterpret_cast<const char *>(buf.data()), buf.size());
            }
            catch (...)
            {
                ec = error::jwe_error::decryption_failed;
                return "";
            }
        }

        /// Generate a random 128-bit (16-byte) IV for CBC.
        std::string generate_iv(std::error_code & /*ec*/) const
        {
            Botan::AutoSeeded_RNG rng;
            std::vector<uint8_t> iv(16);
            rng.randomize(iv.data(), iv.size());
            return std::string(reinterpret_cast<const char *>(iv.data()), iv.size());
        }

        size_t      cek_size() const { return m_cek_size; }
        std::string name()     const { return m_name; }

    private:
        std::string m_name;
        int         m_aes_bits, m_hmac_bits;
        size_t      m_cek_size;

        std::pair<std::string, std::string> split_cek(const std::string &cek) const
        {
            size_t half = cek.size() / 2;
            return {cek.substr(0, half), cek.substr(half)};
        }

        std::string compute_tag(const std::string &mac_key,
                                 const std::string &aad,
                                 const std::string &iv,
                                 const std::string &ciphertext,
                                 std::error_code &ec) const
        {
            try
            {
                // AL = bit-length of AAD as big-endian uint64
                uint64_t aad_bit_len = static_cast<uint64_t>(aad.size()) * 8;
                uint8_t al[8];
                for (int i = 7; i >= 0; --i)
                {
                    al[i] = static_cast<uint8_t>(aad_bit_len & 0xFF);
                    aad_bit_len >>= 8;
                }

                std::string hmac_name = "HMAC(SHA-" + std::to_string(m_hmac_bits) + ")";
                auto hmac = Botan::MessageAuthenticationCode::create_or_throw(hmac_name);
                hmac->set_key(
                    reinterpret_cast<const uint8_t *>(mac_key.data()), mac_key.size());
                hmac->update(
                    reinterpret_cast<const uint8_t *>(aad.data()), aad.size());
                hmac->update(
                    reinterpret_cast<const uint8_t *>(iv.data()), iv.size());
                hmac->update(
                    reinterpret_cast<const uint8_t *>(ciphertext.data()), ciphertext.size());
                hmac->update(al, 8);

                auto mac = hmac->final();
                // Tag = first half of MAC output
                size_t tag_size = mac.size() / 2;
                return std::string(reinterpret_cast<const char *>(mac.data()), tag_size);
            }
            catch (...)
            {
                ec = error::jwe_error::encryption_failed;
                return "";
            }
        }
    };

    struct A128CBC_HS256 : public aes_cbc_hs_base
    {
        A128CBC_HS256() : aes_cbc_hs_base("A128CBC-HS256", 128, 256, 32) {}
    };
    struct A192CBC_HS384 : public aes_cbc_hs_base
    {
        A192CBC_HS384() : aes_cbc_hs_base("A192CBC-HS384", 192, 384, 48) {}
    };
    struct A256CBC_HS512 : public aes_cbc_hs_base
    {
        A256CBC_HS512() : aes_cbc_hs_base("A256CBC-HS512", 256, 512, 64) {}
    };

} // namespace algorithm
} // namespace jwe
