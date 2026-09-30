package chala

import (
	"context"
	"net/http"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	chalav1 "dariyanws/gen/dariya/chala/v1"
)

// The engine image runs under chala's posture — no capabilities, no privilege, uid 65534 — and its
// catalog health check turns HEALTHY only once the engine answers a real RESP PING. This is what
// "available" will mean to nache, so it is checked against the real image rather than assumed.
func TestEngineBecomesHealthy(t *testing.T) {
	acct := testAccount(t)
	h := newHarness(t, 5, acct)

	ok, err := h.docker.ImageExists(context.Background(), "dariya/nache-engine:dev")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Skip("engine image not built — `make engine-image`")
	}

	status, inst, raw := h.run(acct, "engine", map[string]any{"imageId": EngineImage})
	if status != http.StatusOK {
		t.Fatalf("RunInstance = %d: %s", status, raw)
	}
	if inst.GetHealth() == chalav1.InstanceHealth_INSTANCE_HEALTH_NONE {
		t.Fatalf("the engine has no health check")
	}

	deadline := time.Now().Add(30 * time.Second)
	for {
		_, raw := h.call("GET", "/instances/engine", acct, "chala:DescribeInstance", ARN(region, acct, "engine"), nil)
		var resp chalav1.DescribeInstanceResponse
		if err := protojson.Unmarshal(raw, &resp); err != nil {
			t.Fatalf("decoding: %v: %s", err, raw)
		}
		switch resp.GetInstance().GetHealth() {
		case chalav1.InstanceHealth_INSTANCE_HEALTH_HEALTHY:
			return
		case chalav1.InstanceHealth_INSTANCE_HEALTH_UNHEALTHY:
			t.Fatalf("the engine went UNHEALTHY: %s", raw)
		}
		if time.Now().After(deadline) {
			t.Fatalf("not HEALTHY after 30s: %s", raw)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func TestShellHasNoHealthCheck(t *testing.T) {
	acct := testAccount(t)
	h := newHarness(t, 5, acct)
	_, inst, raw := h.run(acct, "sh", shell)
	if inst.GetHealth() != chalav1.InstanceHealth_INSTANCE_HEALTH_NONE {
		t.Fatalf("health = %v: %s", inst.GetHealth(), raw)
	}
}
