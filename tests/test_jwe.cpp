// test_jwe.cpp
//
// Test suite for jose/jwe/jwe_botan_jsoncons.hpp
//
// Build (from tests/):
//   cmake -S . -B build
//   cmake --build build --config Release
//   ./build/test_jwe
//

#include <jose/jwe/jwe_botan_jsoncons.hpp>

#include <iostream>

static int passed = 0;
static int failed = 0;

static void check(const char *name, bool ok)
{
    if (ok) { std::cout << "[PASS] " << name << "\n"; ++passed; }
    else    { std::cout << "[FAIL] " << name << "\n"; ++failed; }
}

// ── PEM test keys (RSA-2048) ──────────────────────────────────────────────────

static const char *RSA_PRIV = R"(-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDGdkf9iN3WBjT/
uEVEQY18FySnuHxJtNTiIjNDn7Mst8gi7+jo00Cyu/U1e3GJGCRLa3hyMKGoNgGp
j3MvgQkQgTYCV/qxzrfImCN5i7JEmVWpsJhzQ9GAwGyUrEYS3NnWkrJKjoCcwsPK
Inqf3pcmiJCN3q10JNBFk0qxWvswJST15HvE1cg3jNFhXBmzVEBzSOrppNBeLUr3
qfSLBcQQHIoTUqSvzTRmuqvQyXzJle+O/PfmepoWObUttKzLhQk5et8dbsVSx6hA
ReRcf+R+1140eotZGUIbtkVztZbjatBcyukmwXGpu+EkOnFhoQh+KDT6D1cLFOp0
0LW9nQ3PAgMBAAECggEACNNoxy8ngmWbRMYKmor5wkt7L1RGfraigv33XqoC+1me
9mLJ7lS6u1gdgwfe2DRxJMN+Q0HDZqokL8i33CR2ZTwBzV/hP7gMN0kAxt5+Covx
Ic8/MF0TO5ETIxd4NE2LCH5UnHky4gXNVDdtUZ/CBA4ts4l0GEas1nNC7pk3s3/X
THtgB6Pb89X6YqywnTXdm+u2ZxOelmA4WWutOJQa/bQqO3GnZeT3ZiGX63dlw/kJ
2GBy+fltBnMzeADLMQqwYvzdxDasCpabf8g25iACi0E77JFBZR2/SuPcEypOaa3v
zKqJNLwq30X5ngsx7HaTd/LXn+Z6nw3NW9w0pIiLYQKBgQDu4N3GQiB+fk+aliOU
TRYrNqnh8ifIMm/ETYj486dtakHCNhkk0tKcJSKAl8+C89wjArywhVl9gCiYOu0l
Cdipe+UbR/Qng2oCeWBZFezeOJjJid/lTON5WnLhzjjoU6CK9ubFt/WfVzroULaU
yN0uIqB0O3RIiMq8BgcA/V2DIQKBgQDUr9K1a+FftaTXhYQJCAoZeMLYD2wFZ4e0
z3UHsLmBv574NWwx8qR9MacYuknBUsdMRRPYqwIxdVPrhbUGCUVNzm1s9NeRtakX
coLBfCmmSiD2zCRV/u8r6RV0KFSInhOpFWc+8h+FQDQJYb04z7T4e70x8dlrN7kg
c9U2YH1i7wKBgHGtqVy0E2qfCZrzYDMvDCG8fdP8vVnURsQQceKncUHskyatQAH6
IigUs/qmRCZ5joVKxCjtDM1gs/Dd+gTqTqU5RKpa76HuNADBakx61qJaJLukVVx1
3rrdhFZZIVPOmFQJc4EcLlOJ24q6/miHvlo6OEmYEZqDHpej9qlN6baBAoGAcyFK
GlLviPO268OmmYz0ip1IO9T9UF+eok26uBL+GDI2R34Dt3X1fJ+oKEaPLks0/yBV
ge/wG/27E78pIr9Z+KhJq7VOC94eTkb6aOphUVbHSVFwSezaYxalOl+qgtmvItQn
M3e1gFgk0v9JgrtM50V0QNj+LH/ZgquxOuI4fZkCgYEA39k87wK5gCYPq1pYZBSN
k7f5pvOp+kB8zLeGITUXpijyTu0mKaHnxbVSJerCHB9vyJqdp8U9FvQcPJBbaxMa
r9MFCjKr/ZHjsJNsQWBfdpBPU29N8JEC40L6LtJ0LlTBDOm9PMvhQnsIw6DCwP/F
Ihl3QFWaFSVUuJl931XDbU4=
-----END PRIVATE KEY-----)";

static const char *RSA_PUB = R"(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxnZH/Yjd1gY0/7hFREGN
fBckp7h8SbTU4iIzQ5+zLLfIIu/o6NNAsrv1NXtxiRgkS2t4cjChqDYBqY9zL4EJ
EIE2Alf6sc63yJgjeYuyRJlVqbCYc0PRgMBslKxGEtzZ1pKySo6AnMLDyiJ6n96X
JoiQjd6tdCTQRZNKsVr7MCUk9eR7xNXIN4zRYVwZs1RAc0jq6aTQXi1K96n0iwXE
EByKE1Kkr800Zrqr0Ml8yZXvjvz35nqaFjm1LbSsy4UJOXrfHW7FUseoQEXkXH/k
ftdeNHqLWRlCG7ZFc7WW42rQXMrpJsFxqbvhJDpxYaEIfig0+g9XCxTqdNC1vZ0N
zwIDAQAB
-----END PUBLIC KEY-----)";

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Encrypt then decrypt; check the recovered plaintext matches.
template <typename AlgEnc, typename AlgDec, typename Enc>
static void roundtrip(const char *test_name,
                      AlgEnc alg_enc, AlgDec alg_dec, Enc enc_alg,
                      const std::string &payload)
{
    std::error_code ec;

    // Encrypt
    std::string token = jwe::create()
        .set_payload(payload)
        .set_key_id("test-key")
        .encrypt(alg_enc, enc_alg, ec);
    check((std::string(test_name) + ": encrypt succeeds").c_str(), !ec && !token.empty());

    // Token must have exactly 4 dots (5 parts)
    size_t dots = 0;
    for (char c : token)
        if (c == '.') ++dots;
    check((std::string(test_name) + ": compact has 5 parts").c_str(), dots == 4);

    // Decrypt
    ec = {};
    auto decoded = jwe::decode(token, ec);
    check((std::string(test_name) + ": decode succeeds").c_str(), !ec);

    ec = {};
    decoded.decrypt(alg_dec, enc_alg, ec);
    check((std::string(test_name) + ": decrypt succeeds").c_str(), !ec);

    ec = {};
    const std::string &recovered = decoded.get_plaintext(ec);
    check((std::string(test_name) + ": plaintext matches").c_str(),
          !ec && recovered == payload);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

static void test_dir_a256gcm()
{
    const std::string key(32, 'K');  // 256-bit direct key
    const std::string payload = "Hello, JWE direct encryption!";
    using namespace jwe::algorithm;
    roundtrip("dir+A256GCM", dir(key), dir(key), A256GCM{}, payload);
}

static void test_dir_a128gcm()
{
    const std::string key(16, 'K');  // 128-bit direct key
    const std::string payload = "Hello, JWE A128GCM!";
    using namespace jwe::algorithm;
    roundtrip("dir+A128GCM", dir(key), dir(key), A128GCM{}, payload);
}

static void test_dir_a128cbc_hs256()
{
    const std::string key(32, 'M');  // 256-bit = 128-bit MAC + 128-bit ENC
    const std::string payload = "CBC-HS256 roundtrip test";
    using namespace jwe::algorithm;
    roundtrip("dir+A128CBC-HS256", dir(key), dir(key), A128CBC_HS256{}, payload);
}

static void test_dir_a256cbc_hs512()
{
    const std::string key(64, 'M');  // 512-bit = 256-bit MAC + 256-bit ENC
    const std::string payload = "CBC-HS512 roundtrip test with some data";
    using namespace jwe::algorithm;
    roundtrip("dir+A256CBC-HS512", dir(key), dir(key), A256CBC_HS512{}, payload);
}

static void test_a256kw_a256gcm()
{
    const std::string kek(32, 'W');  // 256-bit KEK
    const std::string payload = "AES-KW + GCM roundtrip";
    using namespace jwe::algorithm;
    roundtrip("A256KW+A256GCM", A256KW(kek), A256KW(kek), A256GCM{}, payload);
}

static void test_a128kw_a128gcm()
{
    const std::string kek(16, 'W');  // 128-bit KEK
    const std::string payload = "A128KW + A128GCM test";
    using namespace jwe::algorithm;
    roundtrip("A128KW+A128GCM", A128KW(kek), A128KW(kek), A128GCM{}, payload);
}

static void test_a256gcmkw_a256gcm()
{
    const std::string kek(32, 'G');
    const std::string payload = "AES-GCM-KW roundtrip";
    using namespace jwe::algorithm;
    roundtrip("A256GCMKW+A256GCM", A256GCMKW(kek), A256GCMKW(kek), A256GCM{}, payload);
}

static void test_rsa_oaep_256_a256gcm()
{
    const std::string payload = "RSA-OAEP-256 + A256GCM roundtrip";
    using namespace jwe::algorithm;
    roundtrip("RSA-OAEP-256+A256GCM",
              RSA_OAEP_256(RSA_PUB),
              RSA_OAEP_256("", RSA_PRIV),
              A256GCM{},
              payload);
}

static void test_rsa_oaep_a256gcm()
{
    const std::string payload = "RSA-OAEP + A256GCM roundtrip";
    using namespace jwe::algorithm;
    roundtrip("RSA-OAEP+A256GCM",
              RSA_OAEP(RSA_PUB),
              RSA_OAEP("", RSA_PRIV),
              A256GCM{},
              payload);
}

static void test_header_claims()
{
    const std::string key(32, 'H');
    const std::string payload = "header claims test";

    std::error_code ec;
    using namespace jwe::algorithm;

    std::string token = jwe::create()
        .set_payload(payload)
        .set_key_id("my-kid")
        .encrypt(dir(key), A256GCM{}, ec);

    check("header_claims: encrypt succeeds", !ec);

    ec = {};
    auto decoded = jwe::decode(token, ec);
    check("header_claims: decode succeeds", !ec);

    ec = {};
    check("header_claims: alg == dir",    decoded.get_algorithm(ec) == "dir"    && !ec);
    ec = {};
    check("header_claims: enc == A256GCM", decoded.get_enc(ec) == "A256GCM"     && !ec);
    ec = {};
    check("header_claims: kid == my-kid", decoded.get_key_id(ec) == "my-kid"    && !ec);
}

static void test_wrong_key_fails()
{
    const std::string right_key(32, 'R');
    const std::string wrong_key(32, 'W');
    const std::string payload = "secret data";

    std::error_code ec;
    using namespace jwe::algorithm;

    std::string token = jwe::create()
        .set_payload(payload)
        .encrypt(dir(right_key), A256GCM{}, ec);
    check("wrong_key: encrypt succeeds", !ec);

    ec = {};
    auto decoded = jwe::decode(token, ec);
    check("wrong_key: decode succeeds", !ec);

    decoded.decrypt(dir(wrong_key), A256GCM{}, ec);
    check("wrong_key: decrypt with wrong key fails", ec.value() != 0);
}

static void test_wrong_kek_fails()
{
    const std::string right_kek(32, 'R');
    const std::string wrong_kek(32, 'W');
    const std::string payload = "wrapped-key test";

    std::error_code ec;
    using namespace jwe::algorithm;

    std::string token = jwe::create()
        .set_payload(payload)
        .encrypt(A256KW(right_kek), A256GCM{}, ec);
    check("wrong_kek: encrypt succeeds", !ec);

    ec = {};
    auto decoded = jwe::decode(token, ec);
    decoded.decrypt(A256KW(wrong_kek), A256GCM{}, ec);
    check("wrong_kek: decrypt with wrong KEK fails", ec.value() != 0);
}

static void test_invalid_token()
{
    std::error_code ec;
    auto t = jwe::decode("not.a.valid.compact.token.extra", ec);
    check("invalid_token: too many dots fails",  ec.value() != 0);

    ec = {};
    auto t2 = jwe::decode("only.three.parts", ec);
    check("invalid_token: too few parts fails", ec.value() != 0);
}

static void test_empty_payload()
{
    const std::string key(32, 'E');
    const std::string payload = "";
    using namespace jwe::algorithm;
    roundtrip("dir+A256GCM empty payload", dir(key), dir(key), A256GCM{}, payload);
}

static void test_binary_payload()
{
    const std::string key(32, 'B');
    // Payload with null bytes and non-ASCII
    std::string payload;
    for (int i = 0; i < 256; ++i) payload += static_cast<char>(i);
    using namespace jwe::algorithm;
    roundtrip("dir+A256GCM binary payload", dir(key), dir(key), A256GCM{}, payload);
}

// ── main ──────────────────────────────────────────────────────────────────────

int main()
{
    test_dir_a256gcm();
    test_dir_a128gcm();
    test_dir_a128cbc_hs256();
    test_dir_a256cbc_hs512();
    test_a256kw_a256gcm();
    test_a128kw_a128gcm();
    test_a256gcmkw_a256gcm();
    test_rsa_oaep_256_a256gcm();
    test_rsa_oaep_a256gcm();
    test_header_claims();
    test_wrong_key_fails();
    test_wrong_kek_fails();
    test_invalid_token();
    test_empty_payload();
    test_binary_payload();

    std::cout << "\n" << passed << " passed, " << failed << " failed\n";
    return failed == 0 ? 0 : 1;
}
