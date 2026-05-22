// test_jwt.cpp
//
// Test suite for jose/jwt/jwt_botan_jsoncons.hpp
//
// Build (from tests/):
//   cmake -S . -B build
//   cmake --build build --config Release
//   ./build/test_jwt
//


#include <jose/jwt/jwt_botan_jsoncons.hpp>

#include <iostream>
#include <chrono>

static int passed = 0;
static int failed = 0;

static void check(const char *name, bool ok)
{
    if (ok)
    {
        std::cout << "[PASS] " << name << "\n";
        ++passed;
    }
    else
    {
        std::cout << "[FAIL] " << name << "\n";
        ++failed;
    }
}

// ── PEM test keys ─────────────────────────────────────────────────────────────
// RSA-2048 (used for RS256/384/512 and PS256/384/512)
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

// EC P-256 (PKCS#8)
static const char *EC256_PRIV = R"(-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVqFNFue/WZJ/WduI
OUA+V14rF8OKO6ZSLX8GGNAa1FWhRANCAAQMnI6+SalHv1kJHgTbUq7lxrKoCmKg
e2OFrCK6h5tvGqLYchRTRZ3sMcl6Le9SjtKVbIcfXdKMr46cVIGbXd78
-----END PRIVATE KEY-----)";

static const char *EC256_PUB = R"(-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDJyOvkmpR79ZCR4E21Ku5cayqApi
oHtjhawiuoebbxqi2HIUU0Wd7DHJei3vUo7SlWyHH13SjK+OnFSBm13e/A==
-----END PUBLIC KEY-----)";

// EC P-384 (PKCS#8)
static const char *EC384_PRIV = R"(-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCvZry+K9BXpAwfEAC9
FrM0hhhPZI76u33jkybOOpg+vaz52ZB1yV7p5C5/i35yMlqhZANiAASWx9Z3DV2u
zruQwSdGhWbDsQ9+hwUbjFM0gxRhUX8KlTz07aen7VxPGwKxNaX9Rpa6Da3QH6H2
bv8SbzMlf1jAwL/HlV6Z+UyaPRRC5DM5d8+kqRuKKUkas8ire5pMi9I=
-----END PRIVATE KEY-----)";

static const char *EC384_PUB = R"(-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAElsfWdw1drs67kMEnRoVmw7EPfocFG4xT
NIMUYVF/CpU89O2np+1cTxsCsTWl/UaWug2t0B+h9m7/Em8zJX9YwMC/x5VemflM
mj0UQuQzOXfPpKkbiilJGrPIq3uaTIvS
-----END PUBLIC KEY-----)";

// EC P-521 (PKCS#8)
static const char *EC521_PRIV = R"(-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIB7OjHeeyDIluFFw98
buWhBNAAnCxjzGec54eHpz43brK8fBbkXz9gsPFD/iaLZMVApiX5109xqv+6GzsV
Rxbrse2hgYkDgYYABAEuxQf11afiUlWSzlXibjzT2Dfw9TsUCGw844pI5nb7HDAK
MaBsJZTYnRlzlb0tQhWF3OWx4sqhlmPlbvqpQoQm5AAoRFpYE7BR+UvPTbLrvX0t
lG9/BW4OEJrl+u4jsN+W0R3trN/jvxfoMCv2ygsxgGDF/fKPWwC2fy3ktuimrhzl
Aw==
-----END PRIVATE KEY-----)";

static const char *EC521_PUB = R"(-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBLsUH9dWn4lJVks5V4m4809g38PU7
FAhsPOOKSOZ2+xwwCjGgbCWU2J0Zc5W9LUIVhdzlseLKoZZj5W76qUKEJuQAKERa
WBOwUflLz02y6719LZRvfwVuDhCa5fruI7DfltEd7azf478X6DAr9soLMYBgxf3y
j1sAtn8t5Lbopq4c5QM=
-----END PUBLIC KEY-----)";

// ── RFC 7515 Appendix A.1 key (64 raw bytes, base64url AyM1SysPpby...) ───────
static const uint8_t RFC7515_A1_KEY[] = {
    3, 35, 53, 75, 43, 15, 165, 188, 131, 126, 6, 101, 119, 123, 166, 143,
    90, 179, 40, 230, 240, 84, 201, 40, 169, 15, 132, 178, 210, 80, 46, 191,
    211, 251, 90, 146, 210, 6, 71, 239, 150, 138, 180, 195, 119, 98, 61, 34,
    61, 46, 33, 114, 5, 46, 79, 8, 192, 205, 154, 245, 103, 208, 128, 163};

// ── HMAC ──────────────────────────────────────────────────────────────────────

static void test_hs256_roundtrip()
{
    const std::string secret = "supersecret";
    std::error_code ec;
    auto token = jwt::create()
                     .set_issuer("test")
                     .set_subject("user42")
                     .set_payload_claim("role", jwt::claim(std::string("admin")))
                     .sign(jwt::algorithm::hs256{secret}, ec);
    check("hs256 sign no error", !ec);
    check("hs256 token not empty", !token.empty());
    auto decoded = jwt::decode(token, ec);
    check("hs256 decode no error", !ec);
    jwt::verify().allow_algorithm(jwt::algorithm::hs256{secret}).with_issuer("test").verify(decoded, ec);
    check("hs256 verify ok", !ec);
}

static void test_hs256_wrong_secret()
{
    std::error_code ec;
    auto token = jwt::create().set_issuer("test").sign(jwt::algorithm::hs256{"correct"}, ec);
    auto decoded = jwt::decode(token, ec);
    check("hs256 wrong-secret decode ok", !ec);
    jwt::verify().allow_algorithm(jwt::algorithm::hs256{"wrong"}).verify(decoded, ec);
    check("hs256 wrong secret rejected", !!ec);
}

static void test_hs384_roundtrip()
{
    std::error_code ec;
    auto token = jwt::create().set_subject("s384").sign(jwt::algorithm::hs384{"secret384"}, ec);
    check("hs384 sign no error", !ec);
    auto decoded = jwt::decode(token, ec);
    jwt::verify().allow_algorithm(jwt::algorithm::hs384{"secret384"}).verify(decoded, ec);
    check("hs384 verify ok", !ec);
}

static void test_hs512_roundtrip()
{
    std::error_code ec;
    auto token = jwt::create().set_subject("s512").sign(jwt::algorithm::hs512{"secret512"}, ec);
    check("hs512 sign no error", !ec);
    auto decoded = jwt::decode(token, ec);
    jwt::verify().allow_algorithm(jwt::algorithm::hs512{"secret512"}).verify(decoded, ec);
    check("hs512 verify ok", !ec);
}

// ── RSA PKCS1v15 ──────────────────────────────────────────────────────────────

static void test_rs256_roundtrip()
{
    std::error_code ec;
    auto token = jwt::create().set_issuer("rs256-iss").sign(jwt::algorithm::rs256{RSA_PUB, RSA_PRIV}, ec);
    check("rs256 sign no error", !ec);
    check("rs256 token not empty", !token.empty());
    auto decoded = jwt::decode(token, ec);
    check("rs256 decode ok", !ec);
    jwt::verify().allow_algorithm(jwt::algorithm::rs256{RSA_PUB, RSA_PRIV}).with_issuer("rs256-iss").verify(decoded, ec);
    check("rs256 verify ok", !ec);
    ec = {};
    jwt::verify().allow_algorithm(jwt::algorithm::rs256{RSA_PUB, RSA_PRIV}).with_issuer("wrong").verify(decoded, ec);
    check("rs256 wrong issuer rejected", !!ec);
}

static void test_rs384_roundtrip()
{
    std::error_code ec;
    auto token = jwt::create().set_issuer("rs384-iss").sign(jwt::algorithm::rs384{RSA_PUB, RSA_PRIV}, ec);
    check("rs384 sign no error", !ec);
    auto decoded = jwt::decode(token, ec);
    jwt::verify().allow_algorithm(jwt::algorithm::rs384{RSA_PUB, RSA_PRIV}).with_issuer("rs384-iss").verify(decoded, ec);
    check("rs384 verify ok", !ec);
}

static void test_rs512_roundtrip()
{
    std::error_code ec;
    auto token = jwt::create().set_issuer("rs512-iss").sign(jwt::algorithm::rs512{RSA_PUB, RSA_PRIV}, ec);
    check("rs512 sign no error", !ec);
    auto decoded = jwt::decode(token, ec);
    jwt::verify().allow_algorithm(jwt::algorithm::rs512{RSA_PUB, RSA_PRIV}).with_issuer("rs512-iss").verify(decoded, ec);
    check("rs512 verify ok", !ec);
}

// ── RSA-PSS ───────────────────────────────────────────────────────────────────

static void test_ps256_roundtrip()
{
    std::error_code ec;
    auto token = jwt::create().set_issuer("ps256-iss").sign(jwt::algorithm::ps256{RSA_PUB, RSA_PRIV}, ec);
    check("ps256 sign no error", !ec);
    auto decoded = jwt::decode(token, ec);
    jwt::verify().allow_algorithm(jwt::algorithm::ps256{RSA_PUB, RSA_PRIV}).with_issuer("ps256-iss").verify(decoded, ec);
    check("ps256 verify ok", !ec);
}

static void test_ps384_roundtrip()
{
    std::error_code ec;
    auto token = jwt::create().set_issuer("ps384-iss").sign(jwt::algorithm::ps384{RSA_PUB, RSA_PRIV}, ec);
    check("ps384 sign no error", !ec);
    auto decoded = jwt::decode(token, ec);
    jwt::verify().allow_algorithm(jwt::algorithm::ps384{RSA_PUB, RSA_PRIV}).with_issuer("ps384-iss").verify(decoded, ec);
    check("ps384 verify ok", !ec);
}

static void test_ps512_roundtrip()
{
    std::error_code ec;
    auto token = jwt::create().set_issuer("ps512-iss").sign(jwt::algorithm::ps512{RSA_PUB, RSA_PRIV}, ec);
    check("ps512 sign no error", !ec);
    auto decoded = jwt::decode(token, ec);
    jwt::verify().allow_algorithm(jwt::algorithm::ps512{RSA_PUB, RSA_PRIV}).with_issuer("ps512-iss").verify(decoded, ec);
    check("ps512 verify ok", !ec);
}

// ── ECDSA ─────────────────────────────────────────────────────────────────────

static void test_es256_roundtrip()
{
    std::error_code ec;
    auto token = jwt::create().set_issuer("es256-iss").sign(jwt::algorithm::es256{EC256_PUB, EC256_PRIV}, ec);
    check("es256 sign no error", !ec);
    check("es256 token not empty", !token.empty());
    auto decoded = jwt::decode(token, ec);
    check("es256 decode ok", !ec);
    jwt::verify().allow_algorithm(jwt::algorithm::es256{EC256_PUB, EC256_PRIV}).with_issuer("es256-iss").verify(decoded, ec);
    check("es256 verify ok", !ec);
    ec = {};
    jwt::verify().allow_algorithm(jwt::algorithm::es256{EC256_PUB, EC256_PRIV}).with_issuer("wrong").verify(decoded, ec);
    check("es256 wrong issuer rejected", !!ec);
}

static void test_es384_roundtrip()
{
    std::error_code ec;
    auto token = jwt::create().set_issuer("es384-iss").sign(jwt::algorithm::es384{EC384_PUB, EC384_PRIV}, ec);
    check("es384 sign no error", !ec);
    auto decoded = jwt::decode(token, ec);
    jwt::verify().allow_algorithm(jwt::algorithm::es384{EC384_PUB, EC384_PRIV}).with_issuer("es384-iss").verify(decoded, ec);
    check("es384 verify ok", !ec);
}

static void test_es512_roundtrip()
{
    std::error_code ec;
    auto token = jwt::create().set_issuer("es512-iss").sign(jwt::algorithm::es512{EC521_PUB, EC521_PRIV}, ec);
    check("es512 sign no error", !ec);
    auto decoded = jwt::decode(token, ec);
    jwt::verify().allow_algorithm(jwt::algorithm::es512{EC521_PUB, EC521_PRIV}).with_issuer("es512-iss").verify(decoded, ec);
    check("es512 verify ok", !ec);
}

// ── none ──────────────────────────────────────────────────────────────────────

static void test_none_algorithm()
{
    std::error_code ec;
    auto token = jwt::create().set_subject("nobody").sign(jwt::algorithm::none{}, ec);
    check("none sign no error", !ec);
    auto decoded = jwt::decode(token, ec);
    check("none decode ok", !ec);
    check("none alg header", decoded.get_algorithm(ec) == "none" && !ec);
    jwt::verify().allow_algorithm(jwt::algorithm::none{}).verify(decoded, ec);
    check("none verify ok", !ec);
}

static void test_none_not_allowed_by_default()
{
    // A none-signed token must be rejected if the verifier only allows hs256
    std::error_code ec;
    auto token = jwt::create().set_subject("nobody").sign(jwt::algorithm::none{}, ec);
    auto decoded = jwt::decode(token, ec);
    jwt::verify().allow_algorithm(jwt::algorithm::hs256{"key"}).verify(decoded, ec);
    check("none rejected when not allowed", !!ec);
}

// ── Standard claim accessors ──────────────────────────────────────────────────

static void test_standard_claims()
{
    std::error_code ec;
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(1);
    auto nbf = now - std::chrono::minutes(1);
    auto iat = now;

    auto token = jwt::create()
                     .set_issuer("issuer_v")
                     .set_subject("subject_v")
                     .set_audience("audience_v")
                     .set_id("jti-unique-123")
                     .set_expires_at(exp)
                     .set_not_before(nbf)
                     .set_issued_at(iat)
                     .set_payload_claim("custom", jwt::claim(std::string("hello")))
                     .sign(jwt::algorithm::hs256{"k"}, ec);

    auto d = jwt::decode(token, ec);
    check("standard claims decode ok", !ec);

    check("has_issuer", d.has_issuer());
    check("has_subject", d.has_subject());
    check("has_audience", d.has_audience());
    check("has_id", d.has_id());
    check("has_expires", d.has_expires_at());
    check("has_nbf", d.has_not_before());
    check("has_iat", d.has_issued_at());

    check("get_issuer", d.get_issuer(ec) == "issuer_v" && !ec);
    check("get_subject", d.get_subject(ec) == "subject_v" && !ec);
    check("get_id", d.get_id(ec) == "jti-unique-123" && !ec);

    auto custom = d.get_payload_claim("custom", ec);
    check("get custom claim", !ec && custom.as_string(ec) == "hello" && !ec);

    // get_expires_at / get_not_before / get_issued_at return dates
    auto got_exp = d.get_expires_at(ec);
    check("get_expires_at no error", !ec);
    // Verify the stored time is within 2 seconds of what we set
    auto diff_exp = std::chrono::duration_cast<std::chrono::seconds>(got_exp - exp).count();
    check("get_expires_at value ok", diff_exp >= -1 && diff_exp <= 1);
}

static void test_audience_single()
{
    std::error_code ec;
    auto token = jwt::create()
                     .set_issuer("iss")
                     .set_audience("myapp")
                     .sign(jwt::algorithm::hs256{"k"}, ec);
    auto d = jwt::decode(token, ec);
    check("audience single decode ok", !ec);

    jwt::verify()
        .allow_algorithm(jwt::algorithm::hs256{"k"})
        .with_issuer("iss")
        .with_audience("myapp")
        .verify(d, ec);
    check("audience single verify ok", !ec);

    ec = {};
    jwt::verify()
        .allow_algorithm(jwt::algorithm::hs256{"k"})
        .with_audience("other")
        .verify(d, ec);
    check("audience mismatch rejected", !!ec);
}

static void test_jti_claim()
{
    std::error_code ec;
    auto token = jwt::create()
                     .set_id("tok-42")
                     .sign(jwt::algorithm::hs256{"k"}, ec);
    auto d = jwt::decode(token, ec);
    check("jti decode ok", !ec);

    jwt::verify()
        .allow_algorithm(jwt::algorithm::hs256{"k"})
        .with_id("tok-42")
        .verify(d, ec);
    check("jti verify ok", !ec);

    ec = {};
    jwt::verify()
        .allow_algorithm(jwt::algorithm::hs256{"k"})
        .with_id("wrong-id")
        .verify(d, ec);
    check("jti mismatch rejected", !!ec);
}

// ── Claim value types ─────────────────────────────────────────────────────────

static void test_claim_types()
{
    std::error_code ec;

    // int64
    jwt::claim ci(int64_t(-42));
    check("claim int64 type", ci.get_type(ec) == jwt::claim::type::int64 && !ec);
    check("claim int64 value", ci.as_int(ec) == int64_t(-42) && !ec);

    // uint64 — must be > INT64_MAX so is_int64() returns false
    constexpr uint64_t BIG = 10000000000000000000ULL; // 10^19 > INT64_MAX
    jwt::claim cu(BIG);
    check("claim uint64 type", cu.get_type(ec) == jwt::claim::type::uint64 && !ec);
    check("claim uint64 value", cu.as_uint(ec) == BIG && !ec);

    // float
    jwt::claim cf(3.5f);
    check("claim float type", cf.get_type(ec) == jwt::claim::type::number && !ec);
    auto fv = cf.as_number(ec);
    check("claim float value", !ec && fv > 3.4f && fv < 3.6f);

    // string
    jwt::claim cs(std::string("hello"));
    check("claim string type", cs.get_type(ec) == jwt::claim::type::string && !ec);
    check("claim string value", cs.as_string(ec) == "hello" && !ec);

    // bool (via jsoncons::json)
    jwt::claim cb(jsoncons::json(true));
    check("claim bool type", cb.get_type(ec) == jwt::claim::type::boolean && !ec);
    check("claim bool value", cb.as_bool(ec) == true && !ec);

    // set of strings → stored as array
    std::set<std::string> sv = {"alpha", "beta", "gamma"};
    jwt::claim ca(sv);
    check("claim array type", ca.get_type(ec) == jwt::claim::type::array && !ec);
    auto recovered = ca.as_set(ec);
    check("claim set roundtrip", !ec && recovered == sv);

    // Round-trip through a token (reset ec — previous checks are independent)
    ec = {};
    auto token = jwt::create()
                     .set_payload_claim("n", jwt::claim(int64_t(7)))
                     .set_payload_claim("f", jwt::claim(1.5f))
                     .set_payload_claim("s", jwt::claim(std::string("w")))
                     .sign(jwt::algorithm::hs256{"k"}, ec);
    auto d = jwt::decode(token, ec);
    check("claim types token decode ok", !ec);

    auto cn = d.get_payload_claim("n", ec);
    check("claim int in token", !ec && cn.as_int(ec) == 7 && !ec);
    auto cs2 = d.get_payload_claim("s", ec);
    check("claim string in token", !ec && cs2.as_string(ec) == "w" && !ec);
}

// ── Object and array claims ───────────────────────────────────────────────────

static void test_claim_object()
{
    std::error_code ec;

    // Build an object claim via jsoncons::json
    jsoncons::json obj = jsoncons::json::object();
    obj["name"] = "Alice";
    obj["score"] = 42;

    auto token = jwt::create()
                     .set_payload_claim("meta", jwt::claim(obj))
                     .sign(jwt::algorithm::hs256{"k"}, ec);
    check("object claim sign ok", !ec);

    auto d = jwt::decode(token, ec);
    check("object claim decode ok", !ec);

    auto c = d.get_payload_claim("meta", ec);
    check("object claim retrieved", !ec);
    check("object claim type", c.get_type(ec) == jwt::claim::type::object && !ec);

    // Round-trip: re-serialize and check fields survive
    auto recovered = c.to_json();
    check("object field name", recovered["name"].as<std::string>() == "Alice");
    check("object field score", recovered["score"].as<int>() == 42);
}

static void test_claim_array()
{
    std::error_code ec;

    // Build an array claim with mixed-type values via jsoncons::json
    jsoncons::json arr = jsoncons::json::array();
    arr.push_back("first");
    arr.push_back(2);
    arr.push_back(true);

    auto token = jwt::create()
                     .set_payload_claim("items", jwt::claim(arr))
                     .sign(jwt::algorithm::hs256{"k"}, ec);
    check("array claim sign ok", !ec);

    auto d = jwt::decode(token, ec);
    check("array claim decode ok", !ec);

    auto c = d.get_payload_claim("items", ec);
    check("array claim retrieved", !ec);
    check("array claim type", c.get_type(ec) == jwt::claim::type::array && !ec);

    auto recovered = c.to_json();
    check("array size", recovered.size() == 3);
    check("array[0] string", recovered[0].as<std::string>() == "first");
    check("array[1] int", recovered[1].as<int>() == 2);
    check("array[2] bool", recovered[2].as<bool>() == true);
}

// ── Temporal validation ───────────────────────────────────────────────────────

static void test_exp_rejected()
{
    auto past = std::chrono::system_clock::now() - std::chrono::hours(1);
    std::error_code ec;
    auto token = jwt::create()
                     .set_issuer("t")
                     .set_expires_at(past)
                     .sign(jwt::algorithm::hs256{"k"}, ec);
    auto d = jwt::decode(token, ec);
    check("expired decode ok", !ec);
    jwt::verify().allow_algorithm(jwt::algorithm::hs256{"k"}).verify(d, ec);
    check("expired token rejected", !!ec);
}

static void test_exp_future_ok()
{
    auto future = std::chrono::system_clock::now() + std::chrono::hours(1);
    std::error_code ec;
    auto token = jwt::create()
                     .set_expires_at(future)
                     .sign(jwt::algorithm::hs256{"k"}, ec);
    auto d = jwt::decode(token, ec);
    jwt::verify().allow_algorithm(jwt::algorithm::hs256{"k"}).verify(d, ec);
    check("future exp accepted", !ec);
}

static void test_nbf_rejected()
{
    auto future = std::chrono::system_clock::now() + std::chrono::hours(1);
    std::error_code ec;
    auto token = jwt::create()
                     .set_not_before(future)
                     .sign(jwt::algorithm::hs256{"k"}, ec);
    auto d = jwt::decode(token, ec);
    check("nbf-future decode ok", !ec);
    jwt::verify().allow_algorithm(jwt::algorithm::hs256{"k"}).verify(d, ec);
    check("nbf future rejected", !!ec);
}

static void test_leeway()
{
    // Token expired 30 s ago
    auto slightly_past = std::chrono::system_clock::now() - std::chrono::seconds(30);
    std::error_code ec;
    auto token = jwt::create()
                     .set_expires_at(slightly_past)
                     .sign(jwt::algorithm::hs256{"k"}, ec);
    auto d = jwt::decode(token, ec);

    // No leeway → rejected
    jwt::verify().allow_algorithm(jwt::algorithm::hs256{"k"}).verify(d, ec);
    check("leeway=0 expired rejected", !!ec);

    // 60 s leeway → accepted
    ec = {};
    jwt::verify()
        .allow_algorithm(jwt::algorithm::hs256{"k"})
        .leeway(60)
        .verify(d, ec);
    check("leeway=60 near-expired accepted", !ec);
}

// ── Algorithm security ────────────────────────────────────────────────────────

static void test_wrong_algorithm_rejected()
{
    std::error_code ec;
    // Token signed with hs256, verifier allows only hs512
    auto token = jwt::create().set_subject("x").sign(jwt::algorithm::hs256{"k"}, ec);
    auto d = jwt::decode(token, ec);
    jwt::verify().allow_algorithm(jwt::algorithm::hs512{"k"}).verify(d, ec);
    check("wrong algorithm rejected", !!ec);
}

static void test_multiple_algorithms_allowed()
{
    std::error_code ec;
    auto token256 = jwt::create().set_subject("x").sign(jwt::algorithm::hs256{"k"}, ec);
    auto token512 = jwt::create().set_subject("x").sign(jwt::algorithm::hs512{"k"}, ec);

    auto d256 = jwt::decode(token256, ec);
    auto d512 = jwt::decode(token512, ec);

    // Verifier allows both
    auto v = jwt::verify()
                 .allow_algorithm(jwt::algorithm::hs256{"k"})
                 .allow_algorithm(jwt::algorithm::hs512{"k"});
    v.verify(d256, ec);
    check("multi-alg hs256 accepted", !ec);
    ec = {};
    v.verify(d512, ec);
    check("multi-alg hs512 accepted", !ec);
}

// ── Token integrity (tamper detection) ───────────────────────────────────────

static void test_tampered_signature()
{
    std::error_code ec;
    auto token = jwt::create().set_issuer("t").sign(jwt::algorithm::hs256{"key"}, ec);

    // Flip one character in the signature (last segment)
    std::string tampered = token;
    auto dot = tampered.rfind('.');
    tampered[dot + 1] = (tampered[dot + 1] == 'A') ? 'B' : 'A';

    auto d = jwt::decode(tampered, ec);
    if (!ec)
    {
        jwt::verify().allow_algorithm(jwt::algorithm::hs256{"key"}).verify(d, ec);
    }
    check("tampered signature rejected", !!ec);
}

static void test_tampered_payload()
{
    std::error_code ec;
    auto token = jwt::create()
                     .set_issuer("real-issuer")
                     .sign(jwt::algorithm::hs256{"key"}, ec);

    // Flip one character in the payload (middle segment)
    std::string tampered = token;
    auto dot1 = tampered.find('.');
    auto dot2 = tampered.rfind('.');
    if (dot2 > dot1 + 2)
    {
        // change a character in the payload base64url
        size_t mid = (dot1 + 1 + dot2) / 2;
        tampered[mid] = (tampered[mid] == 'A') ? 'B' : 'A';
    }

    // decode may succeed (payload may still be valid base64url+JSON) or fail
    auto d = jwt::decode(tampered, ec);
    bool rejected = !!ec;
    if (!rejected)
    {
        jwt::verify().allow_algorithm(jwt::algorithm::hs256{"key"}).verify(d, ec);
        rejected = !!ec;
    }
    check("tampered payload rejected", rejected);
}

static void test_cross_token_signature()
{
    // Swap the signature of token A onto token B → verify must fail
    std::error_code ec;
    auto tokA = jwt::create().set_issuer("A").sign(jwt::algorithm::hs256{"k"}, ec);
    auto tokB = jwt::create().set_issuer("B").sign(jwt::algorithm::hs256{"k"}, ec);

    // Build a Frankenstein token: header+payload from B, signature from A
    auto dotA = tokA.rfind('.');
    auto dotB = tokB.rfind('.');
    std::string frankenstein = tokB.substr(0, dotB) + "." + tokA.substr(dotA + 1);

    auto d = jwt::decode(frankenstein, ec);
    if (!ec)
    {
        jwt::verify().allow_algorithm(jwt::algorithm::hs256{"k"}).verify(d, ec);
    }
    check("cross-token signature rejected", !!ec);
}

// ── Malformed tokens ──────────────────────────────────────────────────────────

static void test_malformed_tokens()
{
    std::error_code ec;

    jwt::decode("", ec);
    check("empty token rejected", !!ec);

    ec = {};
    jwt::decode("not.a.jwt.with.too.many.dots", ec);
    // library finds first two dots and uses the rest as signature — decode may
    // succeed but we at least verify we don't crash; what matters is that
    // an actually invalid token (no dots at all) fails:
    ec = {};
    jwt::decode("notajwt", ec);
    check("no-dots token rejected", !!ec);

    ec = {};
    jwt::decode("..", ec);
    // Empty header/payload → JSON parse error; we just verify no crash/throw
    check("dots-only no crash", true); // reaching this line is the pass condition

    ec = {};
    // Valid base64url header, garbage payload
    jwt::decode("eyJhbGciOiJIUzI1NiJ9.!!!.aaa", ec);
    check("invalid base64 payload rejected", !!ec);
}

// ── RFC 7515 Appendix A.1 test vector ────────────────────────────────────────
// The RFC 7515 A.1 key is 64 raw bytes (above).  We verify:
//   (a) A token produced by our library with the RFC key can be verified.
//   (b) The RFC-provided base64url-encoded header+payload decodes correctly.

static void test_rfc7515_hs256_vector()
{
    const std::string rfc_key(reinterpret_cast<const char *>(RFC7515_A1_KEY),
                              sizeof(RFC7515_A1_KEY));

    // (a) Sign + verify with the RFC key
    std::error_code ec;
    auto token = jwt::create()
                     .set_issuer("joe")
                     .sign(jwt::algorithm::hs256{rfc_key}, ec);
    check("RFC7515 A.1 sign ok", !ec);

    auto d = jwt::decode(token, ec);
    jwt::verify()
        .allow_algorithm(jwt::algorithm::hs256{rfc_key})
        .with_issuer("joe")
        .verify(d, ec);
    check("RFC7515 A.1 verify with RFC key ok", !ec);

    // (b) Decode the RFC-provided token (compact-JSON payload).
    //     Signature computed independently with Python hmac module:
    //     sig = lliDzOlRAdGUCfCHCPx_uisb6ZfZ1LRQa0OJLeYTTpY
    const std::string rfc_token =
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"
        ".eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
        ".lliDzOlRAdGUCfCHCPx_uisb6ZfZ1LRQa0OJLeYTTpY";

    ec = {};
    auto rfc_decoded = jwt::decode(rfc_token, ec);
    check("RFC7515 A.1 token decode ok", !ec);
    check("RFC7515 A.1 alg == HS256", !ec && rfc_decoded.get_algorithm(ec) == "HS256");
    check("RFC7515 A.1 iss == joe", !ec && rfc_decoded.get_issuer(ec) == "joe");

    // Verify signature (skip exp — token expired in 2011, use large leeway)
    ec = {};
    jwt::verify()
        .allow_algorithm(jwt::algorithm::hs256{rfc_key})
        .leeway(static_cast<size_t>(1UL << 31)) // ~68 years
        .verify(rfc_decoded, ec);
    check("RFC7515 A.1 signature valid", !ec);

    // Wrong key must be rejected
    ec = {};
    jwt::verify()
        .allow_algorithm(jwt::algorithm::hs256{"wrong"})
        .leeway(static_cast<size_t>(1UL << 31))
        .verify(rfc_decoded, ec);
    check("RFC7515 A.1 wrong key rejected", !!ec);
}

// ─────────────────────────────────────────────────────────────────────────────

int main()
{
    std::cout << "── HMAC ──────────────────────────────────────────────────────\n";
    test_hs256_roundtrip();
    test_hs256_wrong_secret();
    test_hs384_roundtrip();
    test_hs512_roundtrip();

    std::cout << "── RSA PKCS1v15 ──────────────────────────────────────────────\n";
    test_rs256_roundtrip();
    test_rs384_roundtrip();
    test_rs512_roundtrip();

    std::cout << "── RSA-PSS ───────────────────────────────────────────────────\n";
    test_ps256_roundtrip();
    test_ps384_roundtrip();
    test_ps512_roundtrip();

    std::cout << "── ECDSA ─────────────────────────────────────────────────────\n";
    test_es256_roundtrip();
    test_es384_roundtrip();
    test_es512_roundtrip();

    std::cout << "── none ──────────────────────────────────────────────────────\n";
    test_none_algorithm();
    test_none_not_allowed_by_default();

    std::cout << "── Claims ────────────────────────────────────────────────────\n";
    test_standard_claims();
    test_audience_single();
    test_jti_claim();
    test_claim_types();
    test_claim_object();
    test_claim_array();

    std::cout << "── Temporal ──────────────────────────────────────────────────\n";
    test_exp_rejected();
    test_exp_future_ok();
    test_nbf_rejected();
    test_leeway();

    std::cout << "── Algorithm security ────────────────────────────────────────\n";
    test_wrong_algorithm_rejected();
    test_multiple_algorithms_allowed();

    std::cout << "── Token integrity ───────────────────────────────────────────\n";
    test_tampered_signature();
    test_tampered_payload();
    test_cross_token_signature();

    std::cout << "── Malformed tokens ──────────────────────────────────────────\n";
    test_malformed_tokens();

    std::cout << "── RFC 7515 vectors ──────────────────────────────────────────\n";
    test_rfc7515_hs256_vector();

    std::cout << "\n"
              << passed << " passed, " << failed << " failed\n";
    return failed == 0 ? 0 : 1;
}
