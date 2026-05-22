cmake_minimum_required(VERSION 3.30)
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake)

project(jose-tests)

find_package(Botan 3.12.0 REQUIRED)
find_package(Jsoncons 1.7.0 REQUIRED)

set(JOSE_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/../include)

# Single Botan amalgamation shared across all test executables.
# Modules cover: HMAC, RSA (PKCS1/PSS), ECDSA, Ed25519, X25519,
# AES-GCM/CBC, AES Key Wrap (RFC 3394), Base64/Hex, SHA-2/3.
botan_generate(botan_all
    system_rng
    auto_rng
    base64
    hex
    sha2_32
    sha2_64
    sha3
    hmac
    pubkey
    rsa
    eme_oaep
    eme_pkcs1
    emsa_pkcs1
    emsa_pssr
    ecdsa
    pcurves_secp256r1
    pcurves_secp384r1
    pcurves_secp521r1
    pcurves_secp256k1
    ed25519
    x25519
    x509
    aes
    gcm
    cbc
    rfc3394
)

# Helper: test executable linked against Botan + jsoncons + jose headers
function(jose_add_test NAME SOURCE)
    add_executable(${NAME} ${SOURCE})
    target_include_directories(${NAME} PRIVATE ${JOSE_INCLUDE_DIR})
    target_link_libraries(${NAME} PRIVATE botan_all Jsoncons::Jsoncons)
endfunction()

jose_add_test(test_jwt test_jwt.cpp)
jose_add_test(test_jws test_jws.cpp)
jose_add_test(test_jwk test_jwk.cpp)
jose_add_test(test_jwe test_jwe.cpp)
