// Cross-language agreement: this C++ signer must reproduce, byte for byte, what the Go signer
// produced when it generated internal/signing/testdata/signing_vectors.txt.
//
// This test is the whole reason the C++ client lives in dariyanWS rather than in the rig. If the
// two implementations ever disagree — a trailing slash, a "+", the order of two query parameters,
// a secret containing a NUL — every request from a C++ client comes back 403, indistinguishable
// from a wrong secret, at whatever hour the two first meet. Here it is a red build instead.
//
// No test framework on purpose: this binary gets built in repos that should inherit nothing.

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "dariya/hmac.hpp"
#include "dariya/sha256.hpp"
#include "dariya/signer.hpp"

namespace {

int g_failures = 0;

void check(bool ok, const std::string& what, const std::string& got = {},
           const std::string& want = {}) {
    if (ok) {
        return;
    }
    ++g_failures;
    std::fprintf(stderr, "FAIL %s\n", what.c_str());
    if (!want.empty() || !got.empty()) {
        std::fprintf(stderr, "   got:  %s\n  want:  %s\n", got.c_str(), want.c_str());
    }
}

std::string from_hex(const std::string& hex) {
    const auto value = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::string out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        const int hi = value(hex[i]);
        const int lo = value(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            continue;
        }
        out.push_back(static_cast<char>((hi << 4) | lo));
    }
    return out;
}

// ---------------------------------------------------------------------------
// SHA-256 and HMAC, against the published vectors
// ---------------------------------------------------------------------------

void test_sha256_nist() {
    check(dariya::to_hex(dariya::Sha256::hash("")) ==
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "sha256 of the empty string");

    check(dariya::to_hex(dariya::Sha256::hash("abc")) ==
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
          "sha256(\"abc\")");

    check(dariya::to_hex(dariya::Sha256::hash(
              "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")) ==
              "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
          "sha256 of the two-block NIST message");

    // A message that lands exactly on a block boundary, and one that forces the length field into
    // an extra block. Both are where a hand-written padding routine goes wrong.
    const std::string sixty_three(63, 'a');
    const std::string sixty_four(64, 'a');
    const std::string fifty_six(56, 'a');
    check(dariya::to_hex(dariya::Sha256::hash(sixty_three)).size() == 64, "63-byte message hashes");
    check(dariya::to_hex(dariya::Sha256::hash(sixty_four)) ==
              "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
          "sha256 of 64 'a's — exact block boundary");
    check(dariya::to_hex(dariya::Sha256::hash(fifty_six)) ==
              "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a",
          "sha256 of 56 'a's — padding spills into a second block");

    // Streaming in pieces must equal hashing in one go.
    dariya::Sha256 streamed;
    streamed.update("abcdbcdecdefdefgefghfghi");
    streamed.update("jhijkijkljklmklmnlmnopnopq");
    const std::string one_shot = dariya::to_hex(dariya::Sha256::hash(
        "abcdbcdecdefdefgefghfghijhijkijkljklmklmnlmnopnopq"));
    check(dariya::to_hex(streamed.finish()) == one_shot, "streamed update matches one-shot hash");
}

void test_hmac_rfc4231() {
    // RFC 4231 test case 1.
    const std::string key(20, '\x0b');
    check(dariya::to_hex(dariya::hmac_sha256(key, "Hi There")) ==
              "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
          "HMAC-SHA256 RFC 4231 case 1");

    // Case 2: a short key, and a message that is not.
    check(dariya::to_hex(dariya::hmac_sha256("Jefe", "what do ya want for nothing?")) ==
              "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
          "HMAC-SHA256 RFC 4231 case 2");

    // Case 3: a key longer than the block, which must be hashed down first. This is the branch a
    // hand-written HMAC most often gets wrong, and no dariyanWS secret is long enough to reach it
    // — so only this test covers it.
    const std::string long_key(131, '\xaa');
    check(dariya::to_hex(dariya::hmac_sha256(long_key,
                                             "Test Using Larger Than Block-Size Key - Hash Key First")) ==
              "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
          "HMAC-SHA256 with a key longer than the block");
}

// ---------------------------------------------------------------------------
// The golden vectors
// ---------------------------------------------------------------------------

struct Case {
    std::string name;
    std::map<std::string, std::string> fields;
};

std::vector<Case> load_vectors(const char* path) {
    std::ifstream in(path);
    if (!in) {
        std::fprintf(stderr, "FATAL cannot open vector file %s\n", path);
        std::exit(2);
    }

    std::vector<Case> cases;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') {
            continue;
        }
        const std::size_t space = line.find(' ');
        const std::string key = line.substr(0, space);
        const std::string value = space == std::string::npos ? "" : line.substr(space + 1);

        if (key == "case") {
            cases.push_back(Case{value, {}});
        } else if (!cases.empty()) {
            cases.back().fields[key] = value;
        }
    }
    return cases;
}

void test_golden_vectors(const char* path) {
    const auto cases = load_vectors(path);
    check(!cases.empty(), "vector file contains cases");

    for (const auto& c : cases) {
        const auto field = [&](const std::string& k) {
            const auto it = c.fields.find(k);
            return it == c.fields.end() ? std::string() : it->second;
        };

        dariya::Request request;
        request.method = field("method");
        request.path = from_hex(field("path"));
        request.query = dariya::parse_query(from_hex(field("query")));
        request.body = from_hex(field("body"));

        dariya::Scope scope;
        scope.access_key_id = field("accesskey");
        scope.region = field("region");
        scope.service = field("service");
        const std::string timestamp = field("timestamp");
        scope.date = timestamp.substr(0, 8);

        const std::string secret = from_hex(field("secret"));

        const std::string canonical = dariya::canonical_string(request, scope, timestamp);
        const std::string want_canonical = from_hex(field("canonical"));
        check(canonical == want_canonical, "canonical string [" + c.name + "]",
              canonical, want_canonical);

        const std::string signature = dariya::sign(request, scope, timestamp, secret);
        check(signature == field("signature"), "signature [" + c.name + "]",
              signature, field("signature"));
    }
}

// The encoding rules, asserted directly as well as through the vectors, so a failure says which
// rule broke rather than only which case broke.
void test_encoding_rules() {
    check(dariya::uri_encode("a b") == "a%20b", "a space is %20, not '+'");
    check(dariya::uri_encode("a+b") == "a%2Bb", "a '+' is %2B, not a space");
    check(dariya::uri_encode("a~b") == "a~b", "a tilde is unreserved and stays literal");
    check(dariya::uri_encode("a/b") == "a%2Fb", "a slash inside a segment is encoded");
    check(dariya::uri_encode("-_.~") == "-_.~", "the unreserved set passes through");
    check(dariya::canonical_path("") == "/", "an empty path is /");
    check(dariya::canonical_path("/a b/c") == "/a%20b/c", "separators survive, segments encode");

    const dariya::QueryParams unsorted{{"z", "26"}, {"a", "1"}, {"m", "13"}};
    check(dariya::canonical_query(unsorted) == "a=1&m=13&z=26", "query parameters sort");

    const dariya::QueryParams repeated{{"tag", "z"}, {"tag", "a"}};
    check(dariya::canonical_query(repeated) == "tag=a&tag=z", "repeated values sort among themselves");
}

}  // namespace

int main(int argc, char** argv) {
    const char* vectors = argc > 1 ? argv[1] : DARIYA_VECTOR_FILE;

    test_sha256_nist();
    test_hmac_rfc4231();
    test_encoding_rules();
    test_golden_vectors(vectors);

    if (g_failures > 0) {
        std::fprintf(stderr, "\n%d check(s) failed\n", g_failures);
        return 1;
    }
    std::printf("all checks passed\n");
    return 0;
}
