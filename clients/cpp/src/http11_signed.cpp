#include "dariya/http11_signed.hpp"

#include <cstdio>
#include <optional>
#include <string_view>

#include "load/http.hpp"

namespace dariya {
namespace {

// Kept in step with internal/signing.MaxSkew. Not shared with Go by any mechanism, which is a
// small duplication the vectors do not cover — so if the Go constant changes, this comment is
// where the reader is told to change it too.
constexpr std::time_t kMaxSkewSeconds = 5 * 60;

bool carries_no_body(int status) {
    return status == 204 || status == 304 || (status >= 100 && status < 200);
}

std::string build_query_string(const QueryParams& query) {
    if (query.empty()) {
        return "";
    }
    // The wire form uses the same encoding as the canonical form, so the two cannot disagree
    // about what was signed — which is exactly the mistake that makes a signature valid on paper
    // and rejected in practice.
    std::string out = "?";
    for (std::size_t i = 0; i < query.size(); ++i) {
        if (i > 0) {
            out += "&";
        }
        out += uri_encode(query[i].first) + "=" + uri_encode(query[i].second);
    }
    return out;
}

}  // namespace

Http11Signed::Http11Signed(Options options) {
    const std::time_t when = options.signed_at != 0 ? options.signed_at : std::time(nullptr);
    expires_at_ = when + kMaxSkewSeconds;

    const std::string timestamp = format_timestamp(when);

    Scope scope;
    scope.access_key_id = options.access_key_id;
    scope.date = timestamp.substr(0, 8);
    scope.region = options.region;
    scope.service = options.service;

    Request signing_request;
    signing_request.method = options.method;
    signing_request.path = options.path;
    signing_request.query = options.query;
    signing_request.body = options.body;

    const std::string signature = sign(signing_request, scope, timestamp, options.secret);
    const std::string authorization = authorization_header(scope, signature);

    std::string out;
    out += options.method + " " + canonical_path(options.path) +
           build_query_string(options.query) + " HTTP/1.1\r\n";
    out += "Host: " + options.host + "\r\n";
    out += "Authorization: " + authorization + "\r\n";
    out += std::string(kDateHeader) + ": " + timestamp + "\r\n";
    out += std::string(kContentSha256Header) + ": " + hash_body(options.body) + "\r\n";

    if (!options.body.empty()) {
        out += "Content-Length: " + std::to_string(options.body.size()) + "\r\n";
        out += "Content-Type: application/json\r\n";
    }
    // No Connection header, matching Http11Get: HTTP/1.1 keeps the connection alive by default,
    // and a rig that closed per request would measure reconnect cost instead of the service.
    out += "\r\n";
    out += options.body;

    request_ = std::move(out);
}

std::span<const char> Http11Signed::request() const {
    return {request_.data(), request_.size()};
}

// Framing is Content-Length only, exactly as Http11Get does it, and for the same reason: a
// response framed at the wrong length desynchronises every request after it on the connection and
// produces wrong latencies with no error at all.
dariyanaap::ResponseState Http11Signed::consume(std::span<const char> response) const {
    const std::string_view text(response.data(), response.size());

    const std::size_t blank = text.find("\r\n\r\n");
    if (blank == std::string_view::npos) {
        return text.size() > 64 * 1024 ? dariyanaap::ResponseState::Malformed
                                       : dariyanaap::ResponseState::NeedMore;
    }

    const std::string_view headers = text.substr(0, blank);
    const std::size_t body_begins = blank + 4;

    if (dariyanaap::http::header_value(headers, "transfer-encoding").has_value()) {
        return dariyanaap::ResponseState::Malformed;
    }

    const std::optional<std::uint64_t> declared = dariyanaap::http::content_length(headers);
    if (!declared) {
        const std::optional<int> status = dariyanaap::http::status_code(response);
        if (status && carries_no_body(*status)) {
            return text.size() == body_begins ? dariyanaap::ResponseState::Complete
                                              : dariyanaap::ResponseState::Malformed;
        }
        return dariyanaap::ResponseState::Malformed;
    }

    const std::size_t total = body_begins + static_cast<std::size_t>(*declared);
    if (text.size() < total) {
        return dariyanaap::ResponseState::NeedMore;
    }
    if (text.size() == total) {
        return dariyanaap::ResponseState::Complete;
    }
    return dariyanaap::ResponseState::Malformed;
}

// 2xx only.
//
// A 401 is a complete, well-formed response and emphatically not a success. Counting it as one
// is the specific way this benchmark could lie: an expired signature would turn the run into a
// measurement of rejection throughput, which is faster than the real path and looks like a win.
bool Http11Signed::succeeded(std::span<const char> response) const {
    const std::optional<int> status = dariyanaap::http::status_code(response);
    return status.has_value() && *status >= 200 && *status < 300;
}

}  // namespace dariya
