#pragma once

#include <chrono>
#include <string>
#include <system_error>
#include <span>

namespace jwt
{
    using date = std::chrono::system_clock::time_point;

    // ── Concepts ──────────────────────────────────────────────────────────────

    template <typename T>
    concept JsonTraitsConcept =
        requires { typename T::value_type; } &&
        requires(
            typename T::value_type &mut_v,
            const typename T::value_type &v,
            const std::string &s) {
            { T::make_empty_array() } -> std::same_as<typename T::value_type>;
            { T::make_empty_object() } -> std::same_as<typename T::value_type>;
            { T::make_string(s) } -> std::same_as<typename T::value_type>;
            T::push_back(mut_v, s);
            T::set_key(mut_v, s, v);
            { T::is_null(v) } -> std::same_as<bool>;
            { T::is_bool(v) } -> std::same_as<bool>;
            { T::is_int64(v) } -> std::same_as<bool>;
            { T::is_uint64(v) } -> std::same_as<bool>;
            { T::is_double(v) } -> std::same_as<bool>;
            { T::is_string(v) } -> std::same_as<bool>;
            { T::is_array(v) } -> std::same_as<bool>;
            { T::is_object(v) } -> std::same_as<bool>;
            { T::is_empty(v) } -> std::same_as<bool>;
            { T::as_string(v) } -> std::convertible_to<std::string>;
            { T::as_int64(v) } -> std::same_as<int64_t>;
            { T::as_uint64(v) } -> std::same_as<uint64_t>;
            { T::as_double(v) } -> std::same_as<double>;
            { T::as_bool(v) } -> std::same_as<bool>;
            T::array_range(v);
            T::object_range(v);
            { T::parse(s) } -> std::same_as<typename T::value_type>;
            { T::serialize(v) } -> std::convertible_to<std::string>;
            { T::elem_key(*T::object_range(v).begin()) } -> std::convertible_to<std::string>;
            { T::elem_value(*T::object_range(v).begin()) } -> std::convertible_to<typename T::value_type>;
            { T::elem_is_string(*T::array_range(v).begin()) } -> std::same_as<bool>;
            { T::elem_as_string(*T::array_range(v).begin()) } -> std::convertible_to<std::string>;
        };

    template <typename T>
    concept CryptoTraitsConcept =
        requires(const std::string &data, std::error_code &ec) {
            { T::base64url_encode(data) } -> std::convertible_to<std::string>;
            { T::base64url_decode(data, ec) } -> std::convertible_to<std::string>;
        };

    template <typename T>
    concept AlgorithmConcept =
        requires(const T &algo,
                 const std::string &data,
                 const std::string &sig,
                 std::error_code &ec) {
            { algo.sign(data, ec) } -> std::convertible_to<std::string>;
            { algo.verify(data, sig, ec) } -> std::same_as<void>;
            { algo.name() } -> std::convertible_to<std::string>;
        };

    template <typename T>
    concept ClockConcept =
        requires(const T &clock) {
            { clock.now() } -> std::convertible_to<date>;
        };

} // namespace jwt
