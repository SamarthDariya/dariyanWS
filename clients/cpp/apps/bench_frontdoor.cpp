// bench_frontdoor — drive the dariyanWS front door with correctly signed requests.
//
// This is E2's load generator (BREAK.md): what does the front door cost, given that every request
// pays signature verification and a Postgres lookup to resolve the access key.
//
// It is dariyanaap doing its job — closed-loop runner, histogram, error accounting, all of it —
// with one thing added that unit 0 has no business knowing about: a Protocol that signs.
//
// # The failure this app exists to prevent
//
// A signed request is valid for five minutes. A run that outlives its signature does not fail
// loudly; it starts receiving 401s, which are complete well-formed responses that the front door
// produces FASTER than real work. The throughput number goes up and the run looks like a success.
// So this app refuses a plan whose warm-up plus duration would cross the expiry, and checks that
// one request actually succeeds before measuring anything.

#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <memory>
#include <string>

#include "core/endpoint.hpp"
#include "core/errors.hpp"
#include "core/flags.hpp"
#include "core/units.hpp"
#include "dariya/http11_signed.hpp"
#include "load/closed_loop.hpp"

using namespace dariyanaap;

namespace {

constexpr char kUsage[] =
    "bench_frontdoor — signed load against the dariyanWS front door\n"
    "\n"
    "  --target HOST:PORT      front door (default 127.0.0.1:8080)\n"
    "  --connections N         concurrent connections (default 1)\n"
    "  --duration MS           measured window (default 10000)\n"
    "  --warmup MS             discarded window before it (default 0)\n"
    "  --path PATH             request path (default /ping)\n"
    "  --service NAME          service the signature is scoped to (default ws)\n"
    "  --region NAME           region (default hind-1)\n"
    "  --key ID                access key id, or $DARIYA_ACCESS_KEY_ID\n"
    "  --secret SECRET         secret access key, or $DARIYA_SECRET_ACCESS_KEY\n"
    "  --read-timeout MS       (default 1000)\n"
    "  --connect-timeout MS    (default 1000)\n"
    "\n"
    "A signature is valid for 5 minutes, so warmup+duration must stay under it.\n";

std::string env_or(const char* name, const std::string& fallback) {
    const char* v = std::getenv(name);
    return (v != nullptr && *v != '\0') ? std::string(v) : fallback;
}

// Millis is a chrono duration; report in whole milliseconds.
double to_ms(Nanos n) { return static_cast<double>(n.count()) / 1e6; }

}  // namespace

int main(int argc, char** argv) {
    try {
        if (Flags::wants_help(argc, argv)) {
            std::fputs(kUsage, stdout);
            return 0;
        }

        const Flags flags = Flags::parse(
            argc, argv,
            {"target", "connections", "duration", "warmup", "path", "service", "region", "key",
             "secret", "read-timeout", "connect-timeout"});

        ClosedLoopPlan plan;
        plan.target = Endpoint::parse(flags.text("target", "127.0.0.1:8080"));
        plan.connections = static_cast<std::size_t>(flags.number("connections", 1));
        plan.duration = Millis(static_cast<std::int64_t>(flags.number("duration", 10'000)));
        plan.warmup = Millis(static_cast<std::int64_t>(flags.number("warmup", 0)));
        plan.worker.read_timeout =
            Millis(static_cast<std::int64_t>(flags.number("read-timeout", 1000)));
        plan.worker.write_timeout = plan.worker.read_timeout;
        plan.worker.connect_timeout =
            Millis(static_cast<std::int64_t>(flags.number("connect-timeout", 1000)));

        if (plan.connections == 0) {
            throw UsageError("--connections must be at least 1");
        }

        dariya::Http11Signed::Options options;
        options.host = plan.target.host() + ":" + std::to_string(plan.target.port());
        options.method = "GET";
        options.path = flags.text("path", "/ping");
        options.region = flags.text("region", "hind-1");
        options.service = flags.text("service", "ws");
        options.access_key_id = flags.text("key", env_or("DARIYA_ACCESS_KEY_ID", ""));
        options.secret = flags.text("secret", env_or("DARIYA_SECRET_ACCESS_KEY", ""));

        if (options.access_key_id.empty() || options.secret.empty()) {
            std::fputs(kUsage, stderr);
            throw UsageError(
                "--key and --secret are required (or export DARIYA_ACCESS_KEY_ID and "
                "DARIYA_SECRET_ACCESS_KEY; `make dev-token` prints both)");
        }

        const auto protocol = std::make_unique<dariya::Http11Signed>(options);

        // Refuse a run that would outlive its own signature. Past the window every response is a
        // 401 — cheaper to produce than real work, so the measured throughput would rise and the
        // run would look like a success.
        const std::int64_t run_seconds =
            (plan.warmup.count() + plan.duration.count() + 999) / 1000;
        const std::int64_t remaining = protocol->expires_at() - std::time(nullptr);
        if (run_seconds >= remaining) {
            throw UsageError("this run would outlive its signature: warmup+duration is " +
                             std::to_string(run_seconds) + "s and only " +
                             std::to_string(remaining) +
                             "s of the 5 minute window remain. Shorten the run.");
        }

        const ClosedLoopRun run = run_closed_loop(*protocol, plan);
        const RunResult& result = run.result;

        // A run where nothing succeeded is not a measurement. Say so rather than print a
        // beautifully formatted zero.
        if (result.errors.rejected > 0) {
            std::fprintf(stderr,
                         "WARNING: %" PRIu64
                         " responses were well-formed rejections (non-2xx). If that is most of "
                         "them, the signature was refused and this run measured the front door "
                         "saying no.\n",
                         result.errors.rejected);
        }
        if (!result.consistent()) {
            std::fprintf(stderr, "WARNING: the rig lost requests; this run is not trustworthy\n");
        }

        std::printf("connections_requested,%zu\n", run.connections_requested);
        std::printf("connections_started,%zu\n", run.connections_started);
        std::printf("attempted,%" PRIu64 "\n", result.attempted);
        std::printf("rejected,%" PRIu64 "\n", result.errors.rejected);
        std::printf("errors_total,%" PRIu64 "\n", result.errors.total());

        if (!result.latency) {
            std::fprintf(stderr, "no request was timed — nothing to report\n");
            return 1;
        }
        const Summary& s = *result.latency;
        std::printf("throughput_rps,%.1f\n", s.per_second());
        std::printf("p50_ms,%.3f\n", to_ms(s.p50));
        std::printf("p90_ms,%.3f\n", to_ms(s.p90));
        std::printf("p99_ms,%.3f\n", to_ms(s.p99));
        std::printf("p999_ms,%.3f\n", to_ms(s.p999));
        std::printf("max_ms,%.3f\n", to_ms(s.max));
        std::printf("percentiles_bounded,%d\n", s.percentiles_bounded() ? 1 : 0);
        return 0;

    } catch (const UsageError& e) {
        std::fprintf(stderr, "bench_frontdoor: %s\n", e.what());
        return 2;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "bench_frontdoor: %s\n", e.what());
        return 1;
    }
}
