#include "dariya/signer.hpp"

#include <algorithm>
#include <cctype>
#include <ctime>
#include <string_view>

#include "dariya/hmac.hpp"
#include "dariya/sha256.hpp"

namespace dariya {
namespace {

constexpr char kUpperHex[] = "0123456789ABCDEF";

bool is_unreserved(unsigned char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
           c == '-' || c == '_' || c == '.' || c == '~';
}

int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

}  // namespace

std::string Scope::str() const {
    return access_key_id + "/" + date + "/" + region + "/" + service;
}

std::string uri_encode(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (const char ch : s) {
        const auto c = static_cast<unsigned char>(ch);
        if (is_unreserved(c)) {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(kUpperHex[c >> 4]);
            out.push_back(kUpperHex[c & 0x0f]);
        }
    }
    return out;
}

std::string canonical_path(std::string_view path) {
    if (path.empty()) {
        return "/";
    }

    std::string out;
    std::size_t start = 0;
    while (true) {
        const std::size_t slash = path.find('/', start);
        const std::string_view segment =
            path.substr(start, slash == std::string_view::npos ? std::string_view::npos
                                                               : slash - start);
        out += uri_encode(segment);
        if (slash == std::string_view::npos) {
            break;
        }
        out.push_back('/');
        start = slash + 1;
    }
    return out;
}

std::string canonical_query(const QueryParams& query) {
    if (query.empty()) {
        return "";
    }

    std::vector<std::string> pairs;
    pairs.reserve(query.size());
    for (const auto& [key, value] : query) {
        pairs.push_back(uri_encode(key) + "=" + uri_encode(value));
    }

    // Sorting the encoded pairs — rather than sorting keys and then values — is what makes this
    // match the Go side exactly, including the case of one key repeated with several values.
    std::sort(pairs.begin(), pairs.end());

    std::string out;
    for (std::size_t i = 0; i < pairs.size(); ++i) {
        if (i > 0) {
            out.push_back('&');
        }
        out += pairs[i];
    }
    return out;
}

std::string hash_body(std::string_view body) {
    return to_hex(Sha256::hash(body));
}

std::string canonical_string(const Request& request, const Scope& scope,
                             const std::string& timestamp) {
    std::string method = request.method;
    std::transform(method.begin(), method.end(), method.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });

    std::string out;
    out += kAlgorithm;
    out += '\n';
    out += method;
    out += '\n';
    out += canonical_path(request.path);
    out += '\n';
    out += canonical_query(request.query);
    out += '\n';
    out += timestamp;
    out += '\n';
    out += hash_body(request.body);
    out += '\n';
    out += scope.str();
    return out;
}

std::string sign(const Request& request, const Scope& scope, const std::string& timestamp,
                 std::string_view secret) {
    const std::string message = canonical_string(request, scope, timestamp);
    const auto mac = hmac_sha256(secret.data(), secret.size(), message.data(), message.size());
    return to_hex(mac);
}

std::string authorization_header(const Scope& scope, const std::string& signature) {
    return std::string(kAlgorithm) + " Credential=" + scope.str() + ", Signature=" + signature;
}

std::string format_timestamp(std::time_t when) {
    std::tm utc{};
#if defined(_WIN32)
    gmtime_s(&utc, &when);
#else
    gmtime_r(&when, &utc);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y%m%dT%H%M%SZ", &utc);
    return buf;
}

QueryParams parse_query(std::string_view raw) {
    QueryParams out;
    if (raw.empty()) {
        return out;
    }

    // Form decoding, which is the inverse of what a URL carries: '+' is a space here, unlike in
    // the canonical form where a space is %20 and a '+' is %2B.
    const auto decode = [](std::string_view s) {
        std::string out;
        out.reserve(s.size());
        for (std::size_t i = 0; i < s.size(); ++i) {
            if (s[i] == '+') {
                out.push_back(' ');
            } else if (s[i] == '%' && i + 2 < s.size()) {
                const int hi = hex_value(s[i + 1]);
                const int lo = hex_value(s[i + 2]);
                if (hi >= 0 && lo >= 0) {
                    out.push_back(static_cast<char>((hi << 4) | lo));
                    i += 2;
                } else {
                    out.push_back(s[i]);
                }
            } else {
                out.push_back(s[i]);
            }
        }
        return out;
    };

    std::size_t start = 0;
    while (start <= raw.size()) {
        const std::size_t amp = raw.find('&', start);
        const std::string_view pair =
            raw.substr(start, amp == std::string_view::npos ? std::string_view::npos : amp - start);
        if (!pair.empty()) {
            const std::size_t eq = pair.find('=');
            if (eq == std::string_view::npos) {
                out.emplace_back(decode(pair), std::string());
            } else {
                out.emplace_back(decode(pair.substr(0, eq)), decode(pair.substr(eq + 1)));
            }
        }
        if (amp == std::string_view::npos) {
            break;
        }
        start = amp + 1;
    }
    return out;
}

}  // namespace dariya
