package irma

import (
	"github.com/nuts-foundation/nuts-auth/auth/pgk"
	"github.com/nuts-foundation/nuts-auth/configuration"
	"github.com/nuts-foundation/nuts-auth/pkg"
	"sync"
	"testing"
)

func TestGetIrmaServer(t *testing.T) {
	t.Run("it fails when the configuration is not initialized", func(t *testing.T) {
		pgk.serverOnce = new(sync.Once)
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected GetIrmaServer() without initialized config to panic")

			}
		}()
		if server := pkg.GetIrmaServer(); server != nil {
			t.Error("expected GetIrmaServer() without initialized config to return nil")
		}
	})
	t.Run("when the config in initialized, the server can be fetched", func(t *testing.T) {
		pgk.serverOnce = new(sync.Once)
		if err := configuration.Initialize("../../testdata", "testconfig"); err != nil {
			t.Error("error while loading config", err)
		}
		if pkg.GetIrmaServer() == nil {
			t.Error("expected an IRMA server instance")
		}
	})
}
