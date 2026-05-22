#pragma once

#include <jsoncons/json.hpp>

#include <string>
#include <cstdint>

namespace jwt
{
    namespace traits
    {

        /**
         * JSON traits implementation backed by danielaparker/jsoncons.
         *
         * Exposes the minimal static interface required by jwt::basic_claim,
         * jwt::basic_decoded_jwt, jwt::basic_builder and jwt::basic_verifier.
         */
        struct jsoncons_json_traits
        {
            // ── Core type ────────────────────────────────────────────────────────────

            using value_type = jsoncons::json;

            // ── Type tags needed for claim construction ───────────────────────────────

            static value_type make_empty_array()
            {
                return value_type(jsoncons::json_array_arg);
            }

            static value_type make_empty_object()
            {
                return value_type(jsoncons::json_object_arg);
            }

            static value_type make_string(const std::string &s)
            {
                return value_type(s);
            }

            // ── Mutation helpers ──────────────────────────────────────────────────────

            static void push_back(value_type &arr, const std::string &s)
            {
                arr.push_back(s);
            }

            static void set_key(value_type &obj, const std::string &key, const value_type &val)
            {
                obj[key] = val;
            }

            // ── Type predicates ───────────────────────────────────────────────────────

            static bool is_null(const value_type &v) { return v.is_null(); }
            static bool is_bool(const value_type &v) { return v.is_bool(); }
            static bool is_int64(const value_type &v) { return v.is_int64(); }
            static bool is_uint64(const value_type &v) { return v.is_uint64(); }
            static bool is_double(const value_type &v) { return v.is_double(); }
            static bool is_string(const value_type &v) { return v.is_string(); }
            static bool is_array(const value_type &v) { return v.is_array(); }
            static bool is_object(const value_type &v) { return v.is_object(); }

            // ── Value extractors ──────────────────────────────────────────────────────

            static std::string as_string(const value_type &v) { return v.as_string(); }
            static int64_t as_int64(const value_type &v) { return v.as_integer<int64_t>(); }
            static uint64_t as_uint64(const value_type &v) { return v.as_integer<uint64_t>(); }
            static double as_double(const value_type &v) { return v.as_double(); }
            static bool as_bool(const value_type &v) { return v.as_bool(); }

            // ── Iteration ─────────────────────────────────────────────────────────────

            static auto array_range(const value_type &v) { return v.array_range(); }
            static auto object_range(const value_type &v) { return v.object_range(); }

            // Accessors for object range elements (jsoncons::json::object_value_type)
            template <typename E>
            static std::string elem_key(const E &e) { return std::string(e.key()); }
            template <typename E>
            static value_type elem_value(const E &e) { return e.value(); }

            // Accessor for array range elements
            template <typename E>
            static bool elem_is_string(const E &e) { return e.is_string(); }
            template <typename E>
            static std::string elem_as_string(const E &e) { return e.as_string(); }

            // ── Serialisation ────────────────────────────────────────────────────────

            /// Parse a JSON string; throws on error (caller wraps in try/catch)
            static value_type parse(const std::string &str)
            {
                return value_type::parse(str);
            }

            static bool is_empty(const value_type &v)
            {
                return v.empty();
            }

            static std::string serialize(const value_type &v)
            {
                std::string out;
                v.dump(out);
                return out;
            }
        };

    } // namespace traits
} // namespace jwt
