#pragma once

#include <string>
#include <utility>
#include <vector>

namespace dariya {

// The dariyanWS edge signing scheme, C++ side (DESIGN.md decision 5).
//
// This file must agree with internal/signing/signing.go byte for byte. The agreement is not
// asserted by reading both — it is asserted by tests/vector_test.cpp against golden vectors the
// Go implementation generates. If the two ever diverge on a trailing slash or a "+", every
// request from a C++ client returns 403, identically to a wrong secret, and nothing says why.

inline constexpr char kAlgorithm[] = "DARIYA1-HMAC-SHA256";

// "20060102T150405Z" in Go's reference layout; strftime "%Y%m%dT%H%M%SZ".
inline constexpr char kDateHeader[] = "X-Dariya-Date";
inline constexpr char kContentSha256Header[] = "X-Dariya-Content-Sha256";

using QueryParams = std::vector<std::pair<std::string, std::string>>;

struct Scope {
    std::string access_key_id;
    std::string date;  // yyyymmdd, and it must agree with the timestamp
    std::string region;
    std::string service;

    std::string str() const;
};

struct Request {
    std::string method;
    std::string path;
    QueryParams query;
    std::string body;
};

// RFC 3986 unreserved-set encoding: everything but A-Z a-z 0-9 - _ . ~ becomes %XX with uppercase
// hex. Applied per byte, not per character, so UTF-8 encodes the same on both sides.
//
// Notably NOT form encoding: a space becomes %20 and a "+" becomes %2B. Go's url.QueryEscape
// would produce "+" for a space, which is the single most likely way these two implementations
// could silently disagree.
std::string uri_encode(std::string_view s);

// Percent-encode each path segment, leaving the separators alone. An empty path is "/".
std::string canonical_path(std::string_view path);

// Sort by the encoded "key=value" string, so parameter order on the wire cannot change the
// signature. Values repeated under one key sort among themselves by the same rule.
std::string canonical_query(const QueryParams& query);

// Hex sha256 of the body. An empty body hashes to sha256("") rather than to a sentinel.
std::string hash_body(std::string_view body);

// The exact bytes both sides MAC over.
std::string canonical_string(const Request& request, const Scope& scope,
                             const std::string& timestamp);

// Lowercase hex HMAC-SHA256 of the canonical string under the secret.
std::string sign(const Request& request, const Scope& scope, const std::string& timestamp,
                 std::string_view secret);

// The Authorization header value.
std::string authorization_header(const Scope& scope, const std::string& signature);

// "%Y%m%dT%H%M%SZ" for a unix timestamp, in UTC.
std::string format_timestamp(std::time_t when);

// Parse a query string of the form Go's url.Values::Encode produces, so a caller holding a URL
// does not have to split it by hand. '+' decodes to a space, as in form encoding — this is about
// reading a URL, not about the canonical form.
QueryParams parse_query(std::string_view raw);

}  // namespace dariya
