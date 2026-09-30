// Package boundary holds one test: the rule that keeps the services in this repo from becoming a
// monorepo by stealth (DESIGN.md decision 13f).
//
// chala and nache live here only until their APIs stop moving, and then graduate to repos of their
// own. That move is mechanical only if, until then, they touch nothing this repo's control plane
// owns. A comment saying so would be read once; this fails the build.
package boundary

import (
	"go/build"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const module = "dariyanws"

// shared is everything a service may import from this module besides its own tree. It is the kit
// a service repo will vendor after graduating, and nothing else: no store, no IAM, no authz, no
// front door. Adding to this list is a decision about what every future service repo carries, so
// it should be as rare as changing the proto.
var shared = []string{
	module + "/gen/",
	module + "/internal/apierr",
	module + "/internal/arn",
	module + "/internal/capability",
	module + "/internal/httpx",
	module + "/internal/servicekit",

	// Added at M8.3, with its first in-service consumer: nache signs its calls to chala. It is
	// the client half of decision 5, standard library only, and every service that calls another
	// through the front door needs exactly this.
	module + "/internal/signing",
}

// services maps each service to the directories that are its code. A service may import from its
// own directories; it may not import from another service's — nache reaches chala over the wire,
// like any other client, or the contract stops being the only coupling.
var services = map[string][]string{
	"chala": {"cmd/chala", "internal/chala"},
	"nache": {"cmd/nache", "internal/nache"},
}

func TestServicesImportOnlyTheSharedKit(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}

	checked := 0
	for service, dirs := range services {
		own := make([]string, 0, len(dirs))
		for _, d := range dirs {
			own = append(own, module+"/"+d)
		}

		for _, dir := range dirs {
			base := filepath.Join(root, dir)
			if _, err := os.Stat(base); os.IsNotExist(err) {
				continue // not built yet
			}
			err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
				if err != nil || !d.IsDir() {
					return err
				}
				pkg, err := build.ImportDir(path, 0)
				if err != nil {
					if _, ok := err.(*build.NoGoError); ok {
						return nil
					}
					return err
				}
				checked++

				// Test files too: a test that reaches into the store is how a service starts
				// depending on the store without its binary showing it.
				imports := append(append(append([]string{}, pkg.Imports...),
					pkg.TestImports...), pkg.XTestImports...)
				for _, imp := range imports {
					if !strings.HasPrefix(imp, module+"/") {
						continue
					}
					if allowed(imp, own) {
						continue
					}
					rel, _ := filepath.Rel(root, path)
					t.Errorf("%s (%s) imports %s, which is outside the shared kit.\n"+
						"A service may use only %v and its own packages (DESIGN.md decision 13f).",
						rel, service, imp, shared)
				}
				return nil
			})
			if err != nil {
				t.Fatalf("walking %s: %v", dir, err)
			}
		}
	}

	if checked == 0 {
		t.Fatal("no service packages were found, so nothing was checked — has a directory moved?")
	}
}

func allowed(imp string, own []string) bool {
	for _, p := range own {
		if imp == p || strings.HasPrefix(imp, p+"/") {
			return true
		}
	}
	for _, p := range shared {
		if strings.HasSuffix(p, "/") {
			if strings.HasPrefix(imp, p) {
				return true
			}
		} else if imp == p || strings.HasPrefix(imp, p+"/") {
			return true
		}
	}
	return false
}
