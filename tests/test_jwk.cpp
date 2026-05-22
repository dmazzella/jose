// test_jwk.cpp
//
// Test suite for jose/jwk/jwk_botan_jsoncons.hpp
//
// Build (from tests/):
//   cmake -S . -B build
//   cmake --build build --config Release
//   ./build/test_jwk
//

#include <jose/jwk/jwk_botan_jsoncons.hpp>

#include <iostream>

static int passed = 0;
static int failed = 0;

static void check(const char *name, bool ok)
{
    if (ok) { std::cout << "[PASS] " << name << "\n"; ++passed; }
    else    { std::cout << "[FAIL] " << name << "\n"; ++failed; }
}

// ── PEM test keys ─────────────────────────────────────────────────────────────

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

static const char *EC256_PRIV = R"(-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgKntssfJDTDYlta+i
AQBO3I8Y6jIIRUSziGVqbVlEaGihRANCAATY1IVqdM3130AfTMDhyPyH/qOA+Ta+
xMNoFc5N61efqZjOfgbjNHAyM449JtaC5L+i1k5yFRx1CRqsteS1WRbO
-----END PRIVATE KEY-----)";

static const char *EC256_PUB = R"(-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2NSFanTN9d9AH0zA4cj8h/6jgPk2
vsTDaBXOTetXn6mYzn4G4zRwMjOOPSbWguS/otZOchUcdQkarLXktVkWzg==
-----END PUBLIC KEY-----)";

// ── Test helpers ──────────────────────────────────────────────────────────────

static void test_rsa_pub_roundtrip()
{
    std::error_code ec;
    auto k = jwk::from_pem_public(RSA_PUB, ec, "rsa-1");
    check("rsa_pub: from_pem_public succeeds", !ec);

    ec = {};
    check("rsa_pub: kty == RSA", k.get_key_type(ec) == jwk::key_type::RSA && !ec);

    ec = {};
    check("rsa_pub: has n/e", k.has_n() && k.has_e());
    check("rsa_pub: no d",    !k.has_d());

    ec = {};
    check("rsa_pub: has kid", k.has_key_id());
    check("rsa_pub: kid == rsa-1", k.get_key_id(ec) == "rsa-1" && !ec);

    // Roundtrip: JWK → PEM
    ec = {};
    std::string pem2 = k.to_pem_public(ec);
    check("rsa_pub: to_pem_public succeeds", !ec && !pem2.empty());
    check("rsa_pub: to_pem_public begins with -----BEGIN PUBLIC KEY-----",
          pem2.find("-----BEGIN PUBLIC KEY-----") != std::string::npos);

    // JSON serialisation
    std::string json = k.to_json();
    check("rsa_pub: to_json not empty", !json.empty());

    // Parse back from JSON
    ec = {};
    auto k2 = jwk::from_json(json, ec);
    check("rsa_pub: from_json roundtrip succeeds", !ec);

    ec = {};
    check("rsa_pub: from_json kty == RSA",
          k2.get_key_type(ec) == jwk::key_type::RSA && !ec);
}

static void test_rsa_priv_roundtrip()
{
    std::error_code ec;
    auto k = jwk::from_pem_private(RSA_PRIV, ec, "rsa-priv-1");
    check("rsa_priv: from_pem_private succeeds", !ec);

    ec = {};
    check("rsa_priv: kty == RSA", k.get_key_type(ec) == jwk::key_type::RSA && !ec);
    check("rsa_priv: has n/e/d/p/q/dp/dq/qi",
          k.has_n() && k.has_e() && k.has_d() &&
          k.has_p() && k.has_q() && k.has_dp() && k.has_dq() && k.has_qi());

    // n and e must be non-empty
    ec = {};
    std::string n = k.get_n(ec);
    check("rsa_priv: get_n succeeds", !ec && !n.empty());

    ec = {};
    std::string pem2 = k.to_pem_private(ec);
    check("rsa_priv: to_pem_private succeeds", !ec && !pem2.empty());
    check("rsa_priv: PEM contains PRIVATE KEY",
          pem2.find("PRIVATE KEY") != std::string::npos);
}

static void test_ec_pub_roundtrip()
{
    std::error_code ec;
    auto k = jwk::from_pem_public(EC256_PUB, ec, "ec-1");
    check("ec_pub: from_pem_public succeeds", !ec);

    ec = {};
    check("ec_pub: kty == EC", k.get_key_type(ec) == jwk::key_type::EC && !ec);

    ec = {};
    check("ec_pub: crv == P-256", k.get_curve(ec) == jwk::ec_curve::P256 && !ec);
    check("ec_pub: has x/y", k.has_x() && k.has_y());
    check("ec_pub: no d",    !k.has_d());

    ec = {};
    std::string pem2 = k.to_pem_public(ec);
    check("ec_pub: to_pem_public succeeds", !ec && !pem2.empty());
    check("ec_pub: PEM begins correctly",
          pem2.find("-----BEGIN PUBLIC KEY-----") != std::string::npos);

    // JSON roundtrip
    std::string json = k.to_json();
    ec = {};
    auto k2 = jwk::from_json(json, ec);
    check("ec_pub: from_json roundtrip", !ec);
    ec = {};
    check("ec_pub: roundtrip kty == EC",
          k2.get_key_type(ec) == jwk::key_type::EC && !ec);
}

static void test_ec_priv_roundtrip()
{
    std::error_code ec;
    auto k = jwk::from_pem_private(EC256_PRIV, ec, "ec-priv-1");
    check("ec_priv: from_pem_private succeeds", !ec);

    ec = {};
    check("ec_priv: kty == EC", k.get_key_type(ec) == jwk::key_type::EC && !ec);
    check("ec_priv: has x/y/d", k.has_x() && k.has_y() && k.has_d());

    ec = {};
    check("ec_priv: crv == P-256", k.get_curve(ec) == jwk::ec_curve::P256 && !ec);

    ec = {};
    std::string pem2 = k.to_pem_private(ec);
    check("ec_priv: to_pem_private succeeds", !ec && !pem2.empty());
}

static void test_oct_roundtrip()
{
    const std::string secret = "0123456789abcdef0123456789abcdef"; // 32 bytes

    std::error_code ec;
    auto k = jwk::from_secret(secret, ec, "sym-1", "A256GCM");
    check("oct: from_secret succeeds", !ec);

    ec = {};
    check("oct: kty == oct", k.get_key_type(ec) == jwk::key_type::oct && !ec);
    check("oct: has k",      k.has_k());
    check("oct: has alg",    k.has_algorithm());

    ec = {};
    check("oct: get_k roundtrip", k.get_k(ec) == secret && !ec);

    ec = {};
    check("oct: to_secret roundtrip", k.to_secret(ec) == secret && !ec);

    ec = {};
    check("oct: kid == sym-1", k.get_key_id(ec) == "sym-1" && !ec);

    // JSON roundtrip
    std::string json = k.to_json();
    ec = {};
    auto k2 = jwk::from_json(json, ec);
    check("oct: from_json roundtrip", !ec);
    ec = {};
    check("oct: roundtrip get_k", k2.get_k(ec) == secret && !ec);
}

static void test_jwks()
{
    // Build a JWKS with two keys
    jwk::jwks ks;

    std::error_code ec;
    ks.add_key(jwk::from_pem_public(RSA_PUB,   ec, "rsa-pub"));
    ks.add_key(jwk::from_pem_public(EC256_PUB, ec, "ec-pub"));

    check("jwks: two keys",     ks.get_keys().size() == 2);

    // find by kid
    auto found = ks.find_by_kid("ec-pub");
    check("jwks: find ec-pub",  found.has_value());

    auto not_found = ks.find_by_kid("unknown");
    check("jwks: find unknown returns nullopt", !not_found.has_value());

    // JSON serialisation and round-trip
    std::string json = ks.to_json();
    check("jwks: to_json not empty", !json.empty());
    check("jwks: to_json contains 'keys'", json.find("\"keys\"") != std::string::npos);

    ec = {};
    jwk::jwks ks2 = jwk::from_jwks_json(json, ec);
    check("jwks: from_jwks_json succeeds",   !ec);
    check("jwks: roundtrip key count == 2",  ks2.get_keys().size() == 2);

    auto found2 = ks2.find_by_kid("rsa-pub");
    check("jwks: roundtrip find rsa-pub",    found2.has_value());
}

static void test_invalid_json()
{
    std::error_code ec;
    auto k = jwk::from_json("{not valid json", ec);
    check("invalid_json: returns error", ec.value() != 0);
}

// ── main ──────────────────────────────────────────────────────────────────────

int main()
{
    test_rsa_pub_roundtrip();
    test_rsa_priv_roundtrip();
    test_ec_pub_roundtrip();
    test_ec_priv_roundtrip();
    test_oct_roundtrip();
    test_jwks();
    test_invalid_json();

    std::cout << "\n" << passed << " passed, " << failed << " failed\n";
    return failed == 0 ? 0 : 1;
}
