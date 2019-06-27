package pkg

import (
	"sync"
	"testing"
)

func TestGetIrmaServer(t *testing.T) {
	t.Run("when the config in initialized, the server can be fetched", func(t *testing.T) {
		serverOnce = new(sync.Once)
		if GetIrmaServer(AuthConfig{}) == nil {
			t.Error("expected an IRMA server instance")
		}
	})
}
