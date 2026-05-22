#pragma once

// Supports both amalgamation and modular Botan 3 builds.
// Amalgamation (standard name): botan/botan_all.h  (output of --amalgamation)
// Amalgamation (custom name):   botan/botan.h      (renamed bundle)
// Modular: only per-module headers are available.

#if __has_include(<botan/botan_all.h>)
#  include <botan/botan_all.h>
#elif __has_include(<botan/botan.h>)
#  include <botan/botan.h>
#else
  // ── Crypto primitives ───────────────────────────────────────────────────
#  include <botan/base64.h>       // base64_encode / base64_decode
#  include <botan/hex.h>          // hex_encode / hex_decode
#  include <botan/hash.h>         // HashFunction
#  include <botan/mac.h>          // MessageAuthenticationCode (HMAC)
#  include <botan/secmem.h>       // secure_vector
#  include <botan/exceptn.h>      // Exception, Invalid_Authentication_Tag

  // ── RNG ─────────────────────────────────────────────────────────────────
#  include <botan/auto_rng.h>     // AutoSeeded_RNG

  // ── Public key infrastructure ───────────────────────────────────────────
#  include <botan/pk_keys.h>      // Private_Key / Public_Key base classes
#  include <botan/pubkey.h>       // PK_Signer, PK_Verifier, PK_Encryptor_EME, PK_Decryptor_EME, Signature_Format
#  include <botan/pkcs8.h>        // PKCS8::load_key / PKCS8::PEM_encode
#  include <botan/x509_key.h>     // X509::load_key / X509::PEM_encode
#  include <botan/data_src.h>     // DataSource_Memory

  // ── EC ───────────────────────────────────────────────────────────────────
#  include <botan/ec_group.h>     // EC_Group
#  include <botan/ec_key.h>       // EC_PrivateKey (base class)
#  include <botan/ec_point.h>     // EC_Point
#  include <botan/ecdsa.h>        // ECDSA_PrivateKey / ECDSA_PublicKey
#  include <botan/asn1_oid.h>     // OID

  // ── RSA ──────────────────────────────────────────────────────────────────
#  include <botan/rsa.h>          // RSA_PublicKey / RSA_PrivateKey
#  include <botan/bigint.h>       // BigInt

  // ── Curve25519 ───────────────────────────────────────────────────────────
#  include <botan/ed25519.h>      // Ed25519_PrivateKey
#  include <botan/curve25519.h>   // X25519_PrivateKey

  // ── Symmetric / AEAD ─────────────────────────────────────────────────────
#  include <botan/symkey.h>       // SymmetricKey, InitializationVector
#  include <botan/aead.h>         // AEAD_Mode, Cipher_Dir
#  include <botan/cipher_mode.h>  // Cipher_Mode
#  include <botan/rfc3394.h>      // rfc3394_keywrap / rfc3394_keyunwrap
#endif
