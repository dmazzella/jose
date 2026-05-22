#pragma once

#include <set>
#include <chrono>
#include <unordered_map>
#include <memory>
#include <sstream>
#include <string>

#include <jose/jwt/jwt_error.hpp>
#include <jose/traits/concepts.hpp>

namespace jwt
{

    /**
     * Convenience wrapper for JSON value.
     * \tparam JsonTraits JSON traits struct (e.g. jwt::traits::jsoncons_json_traits)
     */
    template <JsonTraitsConcept JsonTraits>
    class basic_claim
    {
        typename JsonTraits::value_type val;

    public:
        enum class type
        {
            null,
            boolean,
            number,
            string,
            array,
            object,
            int64,
            uint64
        };

        basic_claim()
            : val()
        {
        }
        basic_claim(const int64_t v)
            : val(v)
        {
        }
        basic_claim(const uint64_t v)
            : val(v)
        {
        }
        basic_claim(const float v)
            : val(v)
        {
        }
        basic_claim(std::string v)
            : val(std::move(v))
        {
        }
        basic_claim(const date &v)
            : val(static_cast<int64_t>(std::chrono::system_clock::to_time_t(v)))
        {
        }
        basic_claim(const std::set<std::string> &v)
            : val(JsonTraits::make_empty_array())
        {
            for (const auto &s : v)
                JsonTraits::push_back(val, s);
        }
        basic_claim(const typename JsonTraits::value_type &v)
            : val(v)
        {
        }

        /**
         * Get wrapped json object
         * \return Wrapped json object
         */
        typename JsonTraits::value_type to_json() const
        {
            return val;
        }

        /**
         * Get type of contained object
         * \return Type
         * \throws std::logic_error An internal error occured
         */
        type get_type(std::error_code &ec) const
        {
            if (JsonTraits::is_null(val))
                return type::null;
            else if (JsonTraits::is_bool(val))
                return type::boolean;
            else if (JsonTraits::is_int64(val))
                return type::int64;
            else if (JsonTraits::is_uint64(val))
                return type::uint64;
            else if (JsonTraits::is_double(val))
                return type::number;
            else if (JsonTraits::is_string(val))
                return type::string;
            else if (JsonTraits::is_array(val))
                return type::array;
            else if (JsonTraits::is_object(val))
                return type::object;
            else
            {
                ec = error::internal_error::internal_logic;
                return type::null;
            }
        }

        /**
         * Get the contained object as a string
         * \return content as string
         * \throws std::bad_cast Content was not a string
         */
        std::string as_string(std::error_code &ec) const
        {
            std::string temp;
            if (!JsonTraits::is_string(val))
            {
                ec = error::internal_error::bad_cast_string;
                return temp;
            }
            return JsonTraits::as_string(val);
        }

        /**
         * Get the contained object as a date
         * \return content as date
         * \throws std::bad_cast Content was not a date
         */
        date as_date(std::error_code &ec) const
        {
            return std::chrono::system_clock::from_time_t(as_int(ec));
        }

        /**
         * Get the contained object as an array
         * \return content as array
         * \throws std::bad_cast Content was not an array
         */
        typename JsonTraits::value_type as_array(std::error_code &ec) const
        {
            if (!JsonTraits::is_array(val))
            {
                ec = error::internal_error::bad_cast_array;
                return JsonTraits::make_empty_array();
            }
            return val;
        }

        /**
         * Get the contained object as a set of strings
         * \return content as set of strings
         * \throws std::bad_cast Content was not a set
         */
        std::set<std::string> as_set(std::error_code &ec) const
        {
            std::set<std::string> res;
            auto arr = as_array(ec); // keep the copy alive for the loop
            if (ec)
                return res;
            for (const auto &e : JsonTraits::array_range(arr))
            {
                if (!JsonTraits::elem_is_string(e))
                {
                    ec = error::internal_error::bad_cast_array;
                    return res;
                }
                res.insert(JsonTraits::elem_as_string(e));
            }
            return res;
        }

        /**
         * Get the contained object as an integer
         * \return content as int
         * \throws std::bad_cast Content was not an int
         */
        int64_t as_int(std::error_code &ec) const
        {
            if (!JsonTraits::is_int64(val))
            {
                ec = error::internal_error::bad_cast_int64;
                return 0;
            }
            return JsonTraits::as_int64(val);
        }

        /**
         * Get the contained object as an integer
         * \return content as uint
         * \throws std::bad_cast Content was not an int
         */
        uint64_t as_uint(std::error_code &ec) const
        {
            if (!JsonTraits::is_uint64(val))
            {
                ec = error::internal_error::bad_cast_uint64;
                return 0;
            }
            return JsonTraits::as_uint64(val);
        }

        /**
         * Get the contained object as a bool
         * \return content as bool
         * \throws std::bad_cast Content was not a bool
         */
        bool as_bool(std::error_code &ec) const
        {
            if (!JsonTraits::is_bool(val))
            {
                ec = error::internal_error::bad_cast_bool;
                return false;
            }
            return JsonTraits::as_bool(val);
        }

        /**
         * Get the contained object as a number
         * \return content as double
         * \throws std::bad_cast Content was not a number
         */
        float as_number(std::error_code &ec) const
        {
            if (!JsonTraits::is_double(val))
            {
                ec = error::internal_error::bad_cast_number;
                return 0.0;
            }
            return static_cast<float>(JsonTraits::as_double(val));
        }
    };

    /**
     * Base class that represents a token payload.
     * Contains Convenience accessors for common claims.
     */
    template <JsonTraitsConcept JsonTraits>
    class basic_payload
    {
    protected:
        std::unordered_map<std::string, basic_claim<JsonTraits>> payload_claims;

    public:
        /**
         * Check if issuer is present ("iss")
         * \return true if present, false otherwise
         */
        bool has_issuer() const noexcept
        {
            return has_payload_claim("iss");
        }
        /**
         * Check if subject is present ("sub")
         * \return true if present, false otherwise
         */
        bool has_subject() const noexcept
        {
            return has_payload_claim("sub");
        }
        /**
         * Check if audience is present ("aud")
         * \return true if present, false otherwise
         */
        bool has_audience() const noexcept
        {
            return has_payload_claim("aud");
        }
        /**
         * Check if expires is present ("exp")
         * \return true if present, false otherwise
         */
        bool has_expires_at() const noexcept
        {
            return has_payload_claim("exp");
        }
        /**
         * Check if not before is present ("nbf")
         * \return true if present, false otherwise
         */
        bool has_not_before() const noexcept
        {
            return has_payload_claim("nbf");
        }
        /**
         * Check if issued at is present ("iat")
         * \return true if present, false otherwise
         */
        bool has_issued_at() const noexcept
        {
            return has_payload_claim("iat");
        }
        /**
         * Check if token id is present ("jti")
         * \return true if present, false otherwise
         */
        bool has_id() const noexcept
        {
            return has_payload_claim("jti");
        }
        /**
         * Get issuer claim
         * \return issuer as string
         * \throws std::runtime_error If claim was not present
         * \throws std::bad_cast Claim was present but not a string (Should not happen in a valid token)
         */
        std::string get_issuer(std::error_code &ec) const
        {
            auto claimN = get_payload_claim("iss", ec);
            if (!ec)
            {
                return claimN.as_string(ec);
            }
            else
            {
                return "";
            }
        }
        /**
         * Get subject claim
         * \return subject as string
         * \throws std::runtime_error If claim was not present
         * \throws std::bad_cast Claim was present but not a string (Should not happen in a valid token)
         */
        std::string get_subject(std::error_code &ec) const
        {
            auto claimN = get_payload_claim("sub", ec);
            if (!ec)
            {
                return claimN.as_string(ec);
            }
            else
            {
                return "";
            }
        }
        /**
         * Get audience claim
         * \return audience as a set of strings or a single string
         * \throws std::runtime_error If claim was not present
         * \throws std::bad_cast Claim was present but not a set (Should not happen in a valid token)
         */
        template <typename T>
        T get_audience(std::error_code &ec) const
        {
            // TBD, Nuertey Odzeyem; assume for now that this method will
            // give us either a proper decoded std::set() or std::string().
            // I will have to later check the decoding to ensure that
            // this assumption holds true.
            auto claimN = get_payload_claim("aud", ec);
            if (!ec)
            {
                if constexpr (std::is_same<T, std::string>::value)
                {
                    std::error_code error1;
                    auto audienceString = claimN.as_string(error1);
                    if (!error1)
                    {
                        return audienceString;
                    }
                    else
                    {
                        return T();
                    }
                }
                else if constexpr (std::is_same<T, std::set<std::string>>::value)
                {
                    std::error_code error2;
                    auto audienceSet = claimN.as_set(error2);
                    if (!error2)
                    {
                        return audienceSet;
                    }
                    else
                    {
                        return T();
                    }
                }
            }
            else
            {
                return T();
            }
        }
        /**
         * Get expires claim
         * \return expires as a date in utc
         * \throws std::runtime_error If claim was not present
         * \throws std::bad_cast Claim was present but not a date (Should not happen in a valid token)
         */
        date get_expires_at(std::error_code &ec) const
        {
            auto claimN = get_payload_claim("exp", ec);
            if (!ec)
            {
                return claimN.as_date(ec);
            }
            else
            {
                return std::chrono::system_clock::from_time_t(0);
            }
        }
        /**
         * Get not valid before claim
         * \return nbf date in utc
         * \throws std::runtime_error If claim was not present
         * \throws std::bad_cast Claim was present but not a date (Should not happen in a valid token)
         */
        date get_not_before(std::error_code &ec) const
        {
            auto claimN = get_payload_claim("nbf", ec);
            if (!ec)
            {
                return claimN.as_date(ec);
            }
            else
            {
                return std::chrono::system_clock::from_time_t(0);
            }
        }
        /**
         * Get issued at claim
         * \return issued at as date in utc
         * \throws std::runtime_error If claim was not present
         * \throws std::bad_cast Claim was present but not a date (Should not happen in a valid token)
         */
        date get_issued_at(std::error_code &ec) const
        {
            auto claimN = get_payload_claim("iat", ec);
            if (!ec)
            {
                return claimN.as_date(ec);
            }
            else
            {
                return std::chrono::system_clock::from_time_t(0);
            }
        }
        /**
         * Get id claim
         * \return id as string
         * \throws std::runtime_error If claim was not present
         * \throws std::bad_cast Claim was present but not a string (Should not happen in a valid token)
         */
        std::string get_id(std::error_code &ec) const
        {
            auto claimN = get_payload_claim("jti", ec);
            if (!ec)
            {
                return claimN.as_string(ec);
            }
            else
            {
                return "";
            }
        }
        /**
         * Check if a payload claim is present
         * \return true if claim was present, false otherwise
         */
        bool has_payload_claim(const std::string &name) const noexcept
        {
            return payload_claims.contains(name);
        }
        /**
         * Get payload claim
         * \return Requested claim
         * \throws std::runtime_error If claim was not present
         */
        basic_claim<JsonTraits> get_payload_claim(const std::string &name, std::error_code &ec) const
        {
            if (!has_payload_claim(name))
            {
                ec = error::internal_error::claim_not_found;
                return basic_claim<JsonTraits>();
            }
            return payload_claims.at(name);
        }
        /**
         * Get all payload claims
         * \return map of claims
         */
        std::unordered_map<std::string, basic_claim<JsonTraits>> get_payload_claims() const
        {
            return payload_claims;
        }
    };

    /**
     * Base class that represents a token header.
     * Contains Convenience accessors for common claims.
     */
    template <JsonTraitsConcept JsonTraits>
    class basic_header
    {
    protected:
        std::unordered_map<std::string, basic_claim<JsonTraits>> header_claims;

    public:
        /**
         * Check if algortihm is present ("alg")
         * \return true if present, false otherwise
         */
        bool has_algorithm() const noexcept
        {
            return has_header_claim("alg");
        }
        /**
         * Check if type is present ("typ")
         * \return true if present, false otherwise
         */
        bool has_type() const noexcept
        {
            return has_header_claim("typ");
        }
        /**
         * Check if content type is present ("cty")
         * \return true if present, false otherwise
         */
        bool has_content_type() const noexcept
        {
            return has_header_claim("cty");
        }
        /**
         * Check if key id is present ("kid")
         * \return true if present, false otherwise
         */
        bool has_key_id() const noexcept
        {
            return has_header_claim("kid");
        }
        /**
         * Get algorithm claim
         * \return algorithm as string
         * \throws std::runtime_error If claim was not present
         * \throws std::bad_cast Claim was present but not a string (Should not happen in a valid token)
         */
        std::string get_algorithm(std::error_code &ec) const
        {
            auto claimN = get_header_claim("alg", ec);
            if (!ec)
            {
                return claimN.as_string(ec);
            }
            else
            {
                return "";
            }
        }
        /**
         * Get type claim
         * \return type as a string
         * \throws std::runtime_error If claim was not present
         * \throws std::bad_cast Claim was present but not a string (Should not happen in a valid token)
         */
        std::string get_type(std::error_code &ec) const
        {
            auto claimN = get_header_claim("typ", ec);
            if (!ec)
            {
                return claimN.as_string(ec);
            }
            else
            {
                return "";
            }
        }
        /**
         * Get content type claim
         * \return content type as string
         * \throws std::runtime_error If claim was not present
         * \throws std::bad_cast Claim was present but not a string (Should not happen in a valid token)
         */
        std::string get_content_type(std::error_code &ec) const
        {

            auto claimN = get_header_claim("cty", ec);
            if (!ec)
            {
                return claimN.as_string(ec);
            }
            else
            {
                return "";
            }
        }
        /**
         * Get key id claim
         * \return key id as string
         * \throws std::runtime_error If claim was not present
         * \throws std::bad_cast Claim was present but not a string (Should not happen in a valid token)
         */
        std::string get_key_id(std::error_code &ec) const
        {
            auto claimN = get_header_claim("kid", ec);
            if (!ec)
            {
                return claimN.as_string(ec);
            }
            else
            {
                return "";
            }
        }
        /**
         * Check if a header claim is present
         * \return true if claim was present, false otherwise
         */
        bool has_header_claim(const std::string &name) const noexcept
        {
            return header_claims.count(name) != 0;
        }
        /**
         * Get header claim
         * \return Requested claim
         * \throws std::runtime_error If claim was not present
         */
        basic_claim<JsonTraits> get_header_claim(const std::string &name, std::error_code &ec) const
        {
            if (!has_header_claim(name))
            {
                ec = error::internal_error::claim_not_found;
                return basic_claim<JsonTraits>();
            }
            return header_claims.at(name);
        }
        /**
         * Get all header claims
         * \return map of claims
         */
        std::unordered_map<std::string, basic_claim<JsonTraits>> get_header_claims() const
        {
            return header_claims;
        }
    };

    /**
     * Class containing all information about a decoded token
     * \tparam JsonTraits      JSON traits struct
     * \tparam CryptoTraits Crypto traits struct (provides base64url_decode)
     */
    template <JsonTraitsConcept JsonTraits, CryptoTraitsConcept CryptoTraits>
    class basic_decoded_jwt : public basic_header<JsonTraits>, public basic_payload<JsonTraits>
    {
    protected:
        /// Unmodifed token, as passed to constructor
        const std::string token;
        /// Header part decoded from base64
        std::string header;
        /// Unmodified header part in base64
        std::string header_base64;
        /// Payload part decoded from base64
        std::string payload;
        /// Unmodified payload part in base64
        std::string payload_base64;
        /// Signature part decoded from base64
        std::string signature;
        /// Unmodified signature part in base64
        std::string signature_base64;

    public:
        /**
         * Constructor
         * Parses a given token
         * \param token The token to parse
         * \throws std::invalid_argument Token is not in correct format
         * \throws std::runtime_error Base64 decoding failed or invalid json
         */
        explicit basic_decoded_jwt(const std::string &token, std::error_code &errorCode)
            : token(token)
        {

            auto hdr_end = token.find('.');
            if (hdr_end == std::string::npos)
            {
                errorCode = error::internal_error::invalid_input;
                return;
            }
            auto payload_end = token.find('.', hdr_end + 1);
            if (payload_end == std::string::npos)
            {
                errorCode = error::internal_error::invalid_input;
                return;
            }
            header = header_base64 = token.substr(0, hdr_end);
            payload = payload_base64 = token.substr(hdr_end + 1, payload_end - hdr_end - 1);
            signature = signature_base64 = token.substr(payload_end + 1);

            std::error_code ec1;
            std::error_code ec2;
            std::error_code ec3;
            header = CryptoTraits::base64url_decode(header, ec1);
            payload = CryptoTraits::base64url_decode(payload, ec2);
            signature = CryptoTraits::base64url_decode(signature, ec3);

            if (ec1)
            {
                errorCode = error::internal_error::invalid_input;
                return;
            }
            else if (ec2)
            {
                errorCode = error::internal_error::invalid_input;
                return;
            }
            else if (ec3)
            {
                errorCode = error::internal_error::invalid_input;
                return;
            }

            auto parse_claims = [](const std::string &str, std::error_code &ec)
            {
                std::unordered_map<std::string, basic_claim<JsonTraits>> res;
                if (str.empty())
                {
                    ec = error::internal_error::invalid_json;
                    return res;
                }
                typename JsonTraits::value_type val;
                try
                {
                    val = JsonTraits::parse(str);
                }
                catch (...)
                {
                    ec = error::internal_error::invalid_json;
                    return res;
                }
                if (JsonTraits::is_empty(val))
                {
                    ec = error::internal_error::invalid_json;
                    return res;
                }

                for (const auto &e : JsonTraits::object_range(val))
                {
                    res.insert({JsonTraits::template elem_key<decltype(e)>(e),
                                basic_claim<JsonTraits>(JsonTraits::template elem_value<decltype(e)>(e))});
                }

                return res;
            };

            this->header_claims = parse_claims(header, errorCode);
            if (!errorCode)
                this->payload_claims = parse_claims(payload, errorCode);
        }

        /**
         * Get token string, as passed to constructor
         * \return token as passed to constructor
         */
        const std::string &get_token() const
        {
            return token;
        }
        /**
         * Get header part as json string
         * \return header part after base64 decoding
         */
        const std::string &get_header() const
        {
            return header;
        }
        /**
         * Get payload part as json string
         * \return payload part after base64 decoding
         */
        const std::string &get_payload() const
        {
            return payload;
        }
        /**
         * Get signature part as json string
         * \return signature part after base64 decoding
         */
        const std::string &get_signature() const
        {
            return signature;
        }
        /**
         * Get header part as base64 string
         * \return header part before base64 decoding
         */
        const std::string &get_header_base64() const
        {
            return header_base64;
        }
        /**
         * Get payload part as base64 string
         * \return payload part before base64 decoding
         */
        const std::string &get_payload_base64() const
        {
            return payload_base64;
        }
        /**
         * Get signature part as base64 string
         * \return signature part before base64 decoding
         */
        const std::string &get_signature_base64() const
        {
            return signature_base64;
        }
    };

    /**
     * Builder class to build and sign a new token
     * Use jwt::create() to get an instance of this class.
     */
    template <JsonTraitsConcept JsonTraits, CryptoTraitsConcept CryptoTraits>
    class basic_builder
    {
        std::unordered_map<std::string, basic_claim<JsonTraits>> header_claims;
        std::unordered_map<std::string, basic_claim<JsonTraits>> payload_claims;

    public:
        basic_builder() = default;

        /**
         * Set a header claim.
         * \param id Name of the claim
         * \param c Claim to add
         * \return *this to allow for method chaining
         */
        basic_builder &set_header_claim(const std::string &id, basic_claim<JsonTraits> c)
        {
            header_claims[id] = std::move(c);
            return *this;
        }
        /**
         * Set a payload claim.
         * \param id Name of the claim
         * \param c Claim to add
         * \return *this to allow for method chaining
         */
        basic_builder &set_payload_claim(const std::string &id, basic_claim<JsonTraits> c)
        {
            payload_claims[id] = std::move(c);
            return *this;
        }
        /**
         * Set algorithm claim
         * You normally don't need to do this, as the algorithm is automatically set if you don't change it.
         * \param str Name of algorithm
         * \return *this to allow for method chaining
         */
        basic_builder &set_algorithm(const std::string &str)
        {
            return set_header_claim("alg", basic_claim<JsonTraits>(str));
        }
        /**
         * Set type claim
         * \param str Type to set
         * \return *this to allow for method chaining
         */
        basic_builder &set_type(const std::string &str)
        {
            return set_header_claim("typ", basic_claim<JsonTraits>(str));
        }
        /**
         * Set content type claim
         * \param str Type to set
         * \return *this to allow for method chaining
         */
        basic_builder &set_content_type(const std::string &str)
        {
            return set_header_claim("cty", basic_claim<JsonTraits>(str));
        }
        /**
         * Set key id claim
         * \param str Key id to set
         * \return *this to allow for method chaining
         */
        basic_builder &set_key_id(const std::string &str)
        {
            return set_header_claim("kid", basic_claim<JsonTraits>(str));
        }
        /**
         * Set issuer claim
         * \param str Issuer to set
         * \return *this to allow for method chaining
         */
        basic_builder &set_issuer(const std::string &str)
        {
            return set_payload_claim("iss", basic_claim<JsonTraits>(str));
        }
        /**
         * Set subject claim
         * \param str Subject to set
         * \return *this to allow for method chaining
         */
        basic_builder &set_subject(const std::string &str)
        {
            return set_payload_claim("sub", basic_claim<JsonTraits>(str));
        }
        /**
         * Set audience claim
         * \param l Audience set (principal recipients)
         * \return *this to allow for method chaining
         */
        basic_builder &set_audience(const std::set<std::string> &l)
        {
            return set_payload_claim("aud", basic_claim<JsonTraits>(l));
        }
        /**
         * Set audience claim
         * \param l Audience string (special case of only 1 recipient)
         * \return *this to allow for method chaining
         */
        basic_builder &set_audience(const std::string &l)
        {
            return set_payload_claim("aud", basic_claim<JsonTraits>(l));
        }
        /**
         * Set expires at claim
         * \param d Expires time
         * \return *this to allow for method chaining
         */
        basic_builder &set_expires_at(const date &d)
        {
            return set_payload_claim("exp", basic_claim<JsonTraits>(d));
        }
        /**
         * Set not before claim
         * \param d First valid time
         * \return *this to allow for method chaining
         */
        basic_builder &set_not_before(const date &d)
        {
            return set_payload_claim("nbf", basic_claim<JsonTraits>(d));
        }
        /**
         * Set issued at claim
         * \param d Issued at time, should be current time
         * \return *this to allow for method chaining
         */
        basic_builder &set_issued_at(const date &d)
        {
            return set_payload_claim("iat", basic_claim<JsonTraits>(d));
        }
        /**
         * Set id claim
         * \param str ID to set
         * \return *this to allow for method chaining
         */
        basic_builder &set_id(const std::string &str)
        {
            return set_payload_claim("jti", basic_claim<JsonTraits>(str));
        }

        /**
         * Sign token and return result
         * \param algo Instance of an algorithm to sign the token with
         * \return Final token as a string
         */
        template <AlgorithmConcept T>
        std::string sign(const T &algo, std::error_code &errorCode)
        {
            this->set_algorithm(algo.name());

            auto obj_header = JsonTraits::make_empty_object();
            for (auto &e : header_claims)
                JsonTraits::set_key(obj_header, e.first, e.second.to_json());

            auto obj_payload = JsonTraits::make_empty_object();
            for (auto &e : payload_claims)
                JsonTraits::set_key(obj_payload, e.first, e.second.to_json());

            std::string header = CryptoTraits::base64url_encode(JsonTraits::serialize(obj_header));
            std::string payload = CryptoTraits::base64url_encode(JsonTraits::serialize(obj_payload));

            std::string token = header + "." + payload;

            return token + "." + CryptoTraits::base64url_encode(algo.sign(token, errorCode));
        }
    };

    /**
     * Verifier class used to check if a decoded token contains all claims required by your application and has a valid signature.
     */
    template <ClockConcept Clock, JsonTraitsConcept JsonTraits, CryptoTraitsConcept CryptoTraits>
    class basic_verifier
    {
        struct algo_base
        {
            virtual ~algo_base() = default;
            virtual void verify(const std::string &data, const std::string &sig, std::error_code &errorCode) = 0;
        };
        template <typename T>
        struct algo : public algo_base
        {
            T alg;
            explicit algo(T a) : alg(a) {}
            virtual void verify(const std::string &data, const std::string &sig, std::error_code &errorCode) override
            {
                alg.verify(data, sig, errorCode);
            }
        };

        /// Required claims
        std::unordered_map<std::string, basic_claim<JsonTraits>> claims;
        /// Leeway time for exp, nbf and iat
        size_t default_leeway = 0;
        /// Instance of clock type
        Clock clock;
        /// Supported algorithms
        std::unordered_map<std::string, std::shared_ptr<algo_base>> algs;

    public:
        /**
         * Constructor for building a new verifier instance
         * \param c Clock instance
         */
        explicit basic_verifier(Clock c)
            : clock(c)
        {
        }

        /**
         * Set default leeway to use.
         * \param leeway Default leeway to use if not specified otherwise
         * \return *this to allow chaining
         */
        basic_verifier &leeway(size_t leeway)
        {
            default_leeway = leeway;
            return *this;
        }
        /**
         * Set leeway for expires at.
         * If not specified the default leeway will be used.
         * \param leeway Set leeway to use for expires at.
         * \return *this to allow chaining
         */
        basic_verifier &expires_at_leeway(size_t leeway)
        {
            return with_claim("exp", basic_claim<JsonTraits>(std::chrono::system_clock::from_time_t(leeway)));
        }
        /**
         * Set leeway for not before.
         * If not specified the default leeway will be used.
         * \param leeway Set leeway to use for not before.
         * \return *this to allow chaining
         */
        basic_verifier &not_before_leeway(size_t leeway)
        {
            return with_claim("nbf", basic_claim<JsonTraits>(std::chrono::system_clock::from_time_t(leeway)));
        }
        /**
         * Set leeway for issued at.
         * If not specified the default leeway will be used.
         * \param leeway Set leeway to use for issued at.
         * \return *this to allow chaining
         */
        basic_verifier &issued_at_leeway(size_t leeway)
        {
            return with_claim("iat", basic_claim<JsonTraits>(std::chrono::system_clock::from_time_t(leeway)));
        }
        /**
         * Set an issuer to check for.
         * Check is casesensitive.
         * \param iss Issuer to check for.
         * \return *this to allow chaining
         */
        basic_verifier &with_issuer(const std::string &iss)
        {
            return with_claim("iss", basic_claim<JsonTraits>(iss));
        }
        /**
         * Set a subject to check for.
         * Check is casesensitive.
         * \param sub Subject to check for.
         * \return *this to allow chaining
         */
        basic_verifier &with_subject(const std::string &sub)
        {
            return with_claim("sub", basic_claim<JsonTraits>(sub));
        }
        /**
         * Set an audience to check for.
         * If any of the specified audiences is not present in the token the check fails.
         * \param aud Audience to check for.
         * \return *this to allow chaining
         */
        basic_verifier &with_audience(const std::set<std::string> &aud)
        {
            return with_claim("aud", basic_claim<JsonTraits>(aud));
        }
        basic_verifier &with_audience(const std::string &aud)
        {
            return with_claim("aud", basic_claim<JsonTraits>(aud));
        }
        /**
         * Set an id to check for.
         * Check is casesensitive.
         * \param id ID to check for.
         * \return *this to allow chaining
         */
        basic_verifier &with_id(const std::string &id)
        {
            return with_claim("jti", basic_claim<JsonTraits>(id));
        }
        /**
         * Specify a claim to check for.
         * \param name Name of the claim to check for
         * \param c Claim to check for
         * \return *this to allow chaining
         */
        basic_verifier &with_claim(const std::string &name, basic_claim<JsonTraits> c)
        {
            claims[name] = c;
            return *this;
        }

        /**
         * Add an algorithm available for checking.
         * \param alg Algorithm to allow
         * \return *this to allow chaining
         */
        template <AlgorithmConcept Algorithm>
        basic_verifier &allow_algorithm(Algorithm alg)
        {
            algs[alg.name()] = std::make_shared<algo<Algorithm>>(alg);
            return *this;
        }

        /**
         * Verify the given token.
         * \param jwt Token to check
         * \throws token_verification_exception Verification failed
         */
        template <CryptoTraitsConcept CT = CryptoTraits>
        void verify(const basic_decoded_jwt<JsonTraits, CT> &jwt, std::error_code &errCode) const
        {
            const std::string data = jwt.get_header_base64() + "." + jwt.get_payload_base64();
            const std::string sig = jwt.get_signature();
            const std::string &algo = jwt.get_algorithm(errCode);

            if (errCode)
            {
                return;
            }
            if (algs.count(algo) == 0)
            {
                errCode = error::token_verification_error::wrong_algorithm;
                return;
            }
            algs.at(algo)->verify(data, sig, errCode);
            if (errCode)
            {
                return;
            }

            auto assert_claim_eq = [](const basic_decoded_jwt<JsonTraits, CT> &jwt, const std::string &key, const basic_claim<JsonTraits> &c, std::error_code &errorCode)
            {
                if (!jwt.has_payload_claim(key))
                {
                    errorCode = error::token_verification_error::wrong_algorithm;
                    return;
                }
                auto jc = jwt.get_payload_claim(key, errorCode);
                if (errorCode)
                {
                    errorCode = error::token_verification_error::missing_claim;
                    return;
                }

                std::error_code ec1;
                std::error_code ec2;
                auto type1 = jc.get_type(ec1);
                auto type2 = c.get_type(ec2);

                if (ec1)
                {
                    errorCode = error::internal_error::internal_logic;
                    return;
                }
                else if (ec2)
                {
                    errorCode = error::internal_error::internal_logic;
                    return;
                }
                else if (type1 != type2)
                {
                    errorCode = error::token_verification_error::claim_type_missmatch;
                    return;
                }
                if (type2 == basic_claim<JsonTraits>::type::int64)
                {
                    std::error_code ec1;
                    std::error_code ec2;
                    auto date1 = jc.as_date(ec1);
                    auto date2 = c.as_date(ec2);
                    if (ec1)
                    {
                        errorCode = error::internal_error::internal_logic;
                        return;
                    }
                    else if (ec2)
                    {
                        errorCode = error::internal_error::internal_logic;
                        return;
                    }
                    else if (date1 != date2)
                    {
                        errorCode = error::token_verification_error::claim_value_missmatch;
                        return;
                    }
                }
                else if (type2 == basic_claim<JsonTraits>::type::array)
                {
                    std::error_code ec1;
                    std::error_code ec2;
                    auto s1 = jc.as_set(ec1);
                    auto s2 = c.as_set(ec2);
                    if (ec1)
                    {
                        errorCode = error::internal_error::internal_logic;
                        return;
                    }
                    else if (ec2)
                    {
                        errorCode = error::internal_error::internal_logic;
                        return;
                    }
                    else if (s1.size() != s2.size())
                    {
                        errorCode = error::token_verification_error::claim_value_missmatch;
                        return;
                    }
                    auto it1 = s1.cbegin();
                    auto it2 = s2.cbegin();
                    while (it1 != s1.cend() && it2 != s2.cend())
                    {
                        if (*it1++ != *it2++)
                        {
                            errorCode = error::token_verification_error::claim_value_missmatch;
                            return;
                        }
                    }
                }
                else if (type2 == basic_claim<JsonTraits>::type::string)
                {
                    std::error_code ec1;
                    std::error_code ec2;
                    auto s1 = jc.as_string(ec1);
                    auto s2 = c.as_string(ec2);
                    if (ec1)
                    {
                        errorCode = error::internal_error::internal_logic;
                        return;
                    }
                    else if (ec2)
                    {
                        errorCode = error::internal_error::internal_logic;
                        return;
                    }
                    if (s1 != s2)
                    {
                        errorCode = error::token_verification_error::claim_value_missmatch;
                        return;
                    }
                }
                else
                {
                    errorCode = error::internal_error::internal_logic;
                    return;
                }
            };

            auto time = std::chrono::system_clock::now();

            if (jwt.has_expires_at())
            {
                std::error_code ec;
                auto exp = jwt.get_expires_at(ec);
                if (ec)
                {
                    errCode = error::internal_error::internal_logic;
                    return;
                }

                if (time > exp + std::chrono::seconds(default_leeway))
                {
                    errCode = error::token_verification_error::token_expired;
                    return;
                }
            }
            if (jwt.has_issued_at())
            {
                std::error_code ec;
                auto iat = jwt.get_issued_at(ec);
                if (ec)
                {
                    errCode = error::internal_error::internal_logic;
                    return;
                }

                if (time < iat - std::chrono::seconds(default_leeway))
                {
                    errCode = error::token_verification_error::token_expired;
                    return;
                }
            }
            if (jwt.has_not_before())
            {
                std::error_code ec;
                auto nbf = jwt.get_not_before(ec);
                if (ec)
                {
                    errCode = error::internal_error::internal_logic;
                    return;
                }

                if (time < nbf - std::chrono::seconds(default_leeway))
                {
                    errCode = error::token_verification_error::token_expired;
                    return;
                }
            }

            for (auto &c : claims)
            {
                if (c.first == "exp" || c.first == "iat" || c.first == "nbf")
                {
                    // Nothing to do here, already checked
                }
                else if (c.first == "aud")
                {
                    if (!jwt.has_audience())
                    {
                        errCode = error::token_verification_error::missing_claim;
                        return;
                    }

                    std::error_code err1;
                    auto expectedSingleAudience = c.second.as_string(err1);
                    if (!err1)
                    {
                        std::string aud = jwt.template get_audience<std::string>(errCode);
                        if (errCode)
                        {
                            return;
                        }

                        if (aud != expectedSingleAudience)
                        {
                            errCode = error::token_verification_error::audience_missmatch;
                            return;
                        }
                    }
                    else
                    {
                        std::error_code err2;
                        auto expectedMultipleAudience = c.second.as_set(err2);
                        if (!err2)
                        {
                            std::set<std::string> aud = jwt.template get_audience<std::set<std::string>>(errCode);
                            if (errCode)
                            {
                                return;
                            }
                            for (auto &e : expectedMultipleAudience)
                            {
                                if (aud.count(e) == 0)
                                {
                                    errCode = error::token_verification_error::missing_claim;
                                    return;
                                }
                            }
                        }
                        else
                        {
                            errCode = error::token_verification_error::missing_claim;
                            return;
                        }
                    }
                }
                else
                {
                    assert_claim_eq(jwt, c.first, c.second, errCode);
                }
            }
        }
    };

    // ── Default clock ─────────────────────────────────────────────────────────

    struct default_clock
    {
        std::chrono::system_clock::time_point now() const
        {
            return std::chrono::system_clock::now();
        }
    };

} // namespace jwt