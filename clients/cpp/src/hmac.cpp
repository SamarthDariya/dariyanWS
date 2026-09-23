#include "dariya/hmac.hpp"

#include <cstring>
#include <vector>

namespace dariya {

Sha256::Digest hmac_sha256(const void* key, std::size_t key_len,
                           const void* message, std::size_t message_len) {
    constexpr std::size_t kBlock = Sha256::kBlockBytes;

    // A key longer than the block is replaced by its hash; a shorter one is zero-padded.
    std::vector<std::uint8_t> normalised(kBlock, 0);
    if (key_len > kBlock) {
        const auto digest = Sha256::hash(key, key_len);
        std::memcpy(normalised.data(), digest.data(), digest.size());
    } else if (key_len > 0) {
        std::memcpy(normalised.data(), key, key_len);
    }

    std::vector<std::uint8_t> inner_pad(kBlock), outer_pad(kBlock);
    for (std::size_t i = 0; i < kBlock; ++i) {
        inner_pad[i] = static_cast<std::uint8_t>(normalised[i] ^ 0x36);
        outer_pad[i] = static_cast<std::uint8_t>(normalised[i] ^ 0x5c);
    }

    Sha256 inner;
    inner.update(inner_pad.data(), inner_pad.size());
    inner.update(message, message_len);
    const auto inner_digest = inner.finish();

    Sha256 outer;
    outer.update(outer_pad.data(), outer_pad.size());
    outer.update(inner_digest.data(), inner_digest.size());
    return outer.finish();
}

bool equal_constant_time(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) {
        return false;
    }
    unsigned char diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
    }
    return diff == 0;
}

}  // namespace dariya
