package irma

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetIrmaServer(t *testing.T) {
	validatorConfig := ValidatorConfig{
		IrmaConfigPath:            "../../../testdata/irma",
		SkipAutoUpdateIrmaSchemas: true,
	}

	t.Run("when the config in initialized, the server can be fetched", func(t *testing.T) {
		serverOnce = new(sync.Once)
		irmaServer, err := GetIrmaServer(validatorConfig)
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, irmaServer, "expected an IRMA server instance")
	})
}
