package pkg

import (
	"testing"

	core "github.com/nuts-foundation/nuts-go-core"
	"github.com/stretchr/testify/assert"
)

func TestAuthInstance(t *testing.T) {
	RegisterTestDependencies(t)
	t.Run("Same instance is returned", func(t *testing.T) {
		assert.Equal(t, AuthInstance(), AuthInstance())
	})

	t.Run("default config is used", func(t *testing.T) {
		assert.Equal(t, AuthInstance().Config, DefaultAuthConfig())
	})
}

func TestAuth_Configure(t *testing.T) {
	RegisterTestDependencies(t)
	t.Run("ok - mode defaults to server", func(t *testing.T) {
		i := TestInstance(t, AuthConfig{})
		_ = i.Configure()
		assert.Equal(t, core.ServerEngineMode, i.Config.Mode)
	})

	t.Run("ok - client mode", func(t *testing.T) {
		i := TestInstance(t, AuthConfig{Mode: core.ClientEngineMode})

		assert.NoError(t, i.Configure())
	})

	t.Run("error - missing actingPartyCn", func(t *testing.T) {
		i := TestInstance(t, AuthConfig{
			Mode:      core.ServerEngineMode,
			PublicUrl: "url",
		})

		assert.Equal(t, ErrMissingActingParty, i.Configure())
	})

	t.Run("error - missing publicUrl", func(t *testing.T) {
		i := TestInstance(t, AuthConfig{
			Mode:          core.ServerEngineMode,
			ActingPartyCn: "url",
		})

		assert.Equal(t, ErrMissingPublicURL, i.Configure())
	})

	t.Run("ok - config valid", func(t *testing.T) {
		i := TestInstance(t, AuthConfig{
			Mode:                      core.ServerEngineMode,
			PublicUrl:                 "url",
			ActingPartyCn:             "url",
			IrmaConfigPath:            "../testdata/irma",
			SkipAutoUpdateIrmaSchemas: true,
		})

		if assert.NoError(t, i.Configure()) {
			// BUG: nuts-auth#23
			assert.True(t, i.Contract.ContractValidator.IsInitialized())
		}
	})

	t.Run("error - IRMA config failure", func(t *testing.T) {
		i := TestInstance(t, AuthConfig{
			Mode:                      core.ServerEngineMode,
			PublicUrl:                 "url",
			ActingPartyCn:             "url",
			IrmaSchemeManager:         "asdasdsad",
			SkipAutoUpdateIrmaSchemas: true,
		})
		err := i.Configure()
		if !assert.NoError(t, err) {
			return
		}
	})
}
