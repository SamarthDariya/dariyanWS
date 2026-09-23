#pragma once

#include <ctime>
#include <string>

#include "dariya/signer.hpp"
#include "load/protocol.hpp"

namespace dariya {

// A signed HTTP/1.1 request, as a dariyanaap::Protocol.
//
// # Why this lives here and not in the rig
//
// dariyanaap is unit 0 and complete. Its Protocol interface is public and taken by const
// reference by run_closed_loop, so a downstream repo supplies its own without the rig being
// reopened — which also keeps HMAC out of a unit that has no use for it, and out of dariyaraah,
// which vendors the rig. The canonical string is part of the contract, not part of the
// measurement, so it belongs beside the Go implementation it has to agree with.
//
// # One signed request, replayed
//
// Protocol::request() is const, the bytes are built once, and the object is shared by every
// connection in a run. A signature cannot therefore be recomputed per request — and does not need
// to be, because decision 5 has no nonce and no replay cache: one signed request stays valid for
// its whole 5-minute window and can be sent as many times as the run likes.
//
// That is a property of the scheme worth naming rather than quietly exploiting: **the protocol
// permits unlimited replay inside the skew window.** SigV4 has the same property and relies on
// TLS plus the window to contain it. The consequence here is a hard constraint on the rig: a run
// must finish inside MaxSkew, or every request after the boundary returns 401 and the throughput
// number becomes a measurement of how fast the front door can reject things.
class Http11Signed : public dariyanaap::Protocol {
public:
    struct Options {
        std::string host;  // Host header, e.g. "127.0.0.1:8080"
        std::string method = "GET";
        std::string path = "/ping";
        QueryParams query;
        std::string body;

        std::string access_key_id;
        std::string secret;
        std::string region = "hind-1";
        std::string service = "ws";

        // Defaults to now. Injectable so a test can pin it.
        std::time_t signed_at = 0;
    };

    explicit Http11Signed(Options options);

    std::span<const char> request() const override;
    dariyanaap::ResponseState consume(std::span<const char> response) const override;
    bool succeeded(std::span<const char> response) const override;

    // When this signature stops being accepted. The runner cannot enforce it — Protocol has
    // nowhere to report it — so the bench app checks it before starting and refuses a plan whose
    // duration would cross it. A run that silently turns into 401s produces a number that looks
    // real and is not.
    std::time_t expires_at() const { return expires_at_; }

    // Exposed for the smoke check the bench app runs before measuring.
    const std::string& raw_request() const { return request_; }

private:
    std::string request_;
    std::time_t expires_at_ = 0;
};

}  // namespace dariya
