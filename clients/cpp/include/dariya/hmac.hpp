#pragma once

#include <cstddef>
#include <string>
#include <string_view>

#include "dariya/sha256.hpp"

namespace dariya {

// HMAC-SHA256 (RFC 2104).
//
// The key is taken as bytes and length, never as a C string: a secret is 30 random bytes base64'd
// today, but the Go vectors include one containing an embedded NUL precisely so an implementation
// that reaches for strlen fails here and not in production.
Sha256::Digest hmac_sha256(const void* key, std::size_t key_len,
                           const void* message, std::size_t message_len);

inline Sha256::Digest hmac_sha256(std::string_view key, std::string_view message) {
    return hmac_sha256(key.data(), key.size(), message.data(), message.size());
}

// Constant-time comparison, for anyone verifying rather than signing. A byte-by-byte compare
// leaks how much of a guessed signature was right.
bool equal_constant_time(std::string_view a, std::string_view b);

}  // namespace dariya
