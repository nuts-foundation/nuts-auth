package pkg

import (
	"sync"
	"testing"
)

func TestGetIrmaServer(t *testing.T) {
	authConfig := AuthConfig{
		IrmaConfigPath:            "../testdata/irma",
		SkipAutoUpdateIrmaSchemas: true,
	}

	t.Run("when the config in initialized, the server can be fetched", func(t *testing.T) {
		serverOnce = new(sync.Once)
		if GetIrmaServer(authConfig) == nil {
			t.Error("expected an IRMA server instance")
		}
	})
}
