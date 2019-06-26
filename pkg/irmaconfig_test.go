package pkg

import (
	"github.com/nuts-foundation/nuts-auth/configuration"
	"sync"
	"testing"
)

func TestGetIrmaServer(t *testing.T) {
	t.Run("when the config in initialized, the server can be fetched", func(t *testing.T) {
		serverOnce = new(sync.Once)
		if err := configuration.Initialize("../../testdata", "testconfig"); err != nil {
			t.Error("error while loading config", err)
		}
		if GetIrmaServer(AuthConfig{}) == nil {
			t.Error("expected an IRMA server instance")
		}
	})
}
