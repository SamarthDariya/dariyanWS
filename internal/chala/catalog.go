package chala

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"dariyanws/internal/chala/docker"
)

// Image is one catalog entry — the AMI analogue (DESIGN.md decision 13b).
//
// A caller names an image by id and never by registry reference. Letting callers choose any
// reference would make chala a way to run arbitrary code the operator has never seen; with a
// catalog, the set of things that can run in the region is a list in this file.
type Image struct {
	ID          string
	Description string

	// Ref is the registry reference. Pulled at boot, never at RunInstance, so that starting an
	// instance takes seconds and a registry outage cannot fail one.
	Ref string

	// Cmd, if set, overrides the image's own entrypoint arguments.
	Cmd []string

	MemoryBytes int64
	PidsLimit   int64

	// Healthcheck is what HEALTHY means for this image.
	Healthcheck *docker.Healthcheck

	// Local images are built in this region, not pulled: the dariyanache engine is built from the
	// track repo by `make engine-image`. A local image that has not been built is reported as
	// unavailable rather than failing chala's boot, so a region that never runs a cache does not
	// have to build one.
	Local bool
}

// EngineImage is the dariyanache engine, the image nache's nodes run.
const EngineImage = "img-nache-engine"

// DefaultCatalog is what chala runs unless told otherwise.
func DefaultCatalog() []Image {
	return []Image{
		{
			ID:          EngineImage,
			Description: "The dariyanache engine, listening on 6379. Run by nache, not by hand.",
			Ref:         "dariya/nache-engine:dev",
			Local:       true,
			MemoryBytes: 256 << 20,
			PidsLimit:   256,
			// A real PING in RESP, because the engine accepts arrays only — inline "PING\r\n"
			// is a protocol error. The check is that the engine answers, not that the port is open.
			Healthcheck: &docker.Healthcheck{
				Shell:       `printf '*1\r\n$4\r\nPING\r\n' | nc -w 1 127.0.0.1 6379 | grep -q PONG`,
				Interval:    time.Second,
				Timeout:     time.Second,
				StartPeriod: 5 * time.Second,
				Retries:     3,
			},
		},
		{
			ID:          "img-shell",
			Description: "A shell on the account network: the client, the bastion, the thing that runs `nc`.",
			Ref:         "busybox:1.36",
			// PID 1 does nothing, forever. Terminate is a SIGKILL, so no signal handling is needed.
			Cmd:         []string{"sh", "-c", "while :; do sleep 3600; done"},
			MemoryBytes: 64 << 20,
			PidsLimit:   64,
		},
	}
}

type catalog map[string]Image

func newCatalog(images []Image) (catalog, error) {
	c := catalog{}
	for _, img := range images {
		if img.ID == "" || img.Ref == "" {
			return nil, fmt.Errorf("chala: catalog entry %+v needs an id and a ref", img)
		}
		if _, dup := c[img.ID]; dup {
			return nil, fmt.Errorf("chala: catalog lists %s twice", img.ID)
		}
		c[img.ID] = img
	}
	return c, nil
}

// PrepareImages pulls every catalog image the daemon does not have yet.
func (s *Server) PrepareImages(ctx context.Context, log *slog.Logger) error {
	for _, img := range s.catalog {
		ok, err := s.docker.ImageExists(ctx, img.Ref)
		if err != nil {
			return err
		}
		if ok {
			continue
		}
		if img.Local {
			log.Warn("catalog image not built; RunInstance with it will be refused",
				"image_id", img.ID, "ref", img.Ref, "build", "make engine-image")
			s.unavailable[img.ID] = true
			continue
		}
		log.Info("pulling catalog image", "image_id", img.ID, "ref", img.Ref)
		if err := s.docker.PullImage(ctx, img.Ref); err != nil {
			return fmt.Errorf("chala: pulling %s (%s): %w", img.ID, img.Ref, err)
		}
	}
	return nil
}
