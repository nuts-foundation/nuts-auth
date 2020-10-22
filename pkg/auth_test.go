package pkg

import (
	"os"
	"testing"

	"github.com/nuts-foundation/nuts-auth/pkg/services/contract"
	crypto "github.com/nuts-foundation/nuts-crypto/pkg"
	core "github.com/nuts-foundation/nuts-go-core"
	testIo "github.com/nuts-foundation/nuts-go-test/io"
	registry "github.com/nuts-foundation/nuts-registry/pkg"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestAuthInstance(t *testing.T) {
	registerTestDependencies(t)
	t.Run("Same instance is returned", func(t *testing.T) {
		assert.Equal(t, AuthInstance(), AuthInstance())
	})

	t.Run("default config is used", func(t *testing.T) {
		assert.Equal(t, AuthInstance().Config, DefaultAuthConfig())
	})
}

func TestAuth_Configure(t *testing.T) {
	registerTestDependencies(t)
	t.Run("ok - mode defaults to server", func(t *testing.T) {
		i := testInstance(t, AuthConfig{})
		_ = i.Configure()
		assert.Equal(t, core.ServerEngineMode, i.Config.Mode)
	})

	t.Run("ok - client mode", func(t *testing.T) {
		i := testInstance(t, AuthConfig{Mode: core.ClientEngineMode})

		assert.NoError(t, i.Configure())
	})

	t.Run("error - missing actingPartyCn", func(t *testing.T) {
		i := testInstance(t, AuthConfig{
			Mode:      core.ServerEngineMode,
			PublicUrl: "url",
		})

		assert.Equal(t, contract.ErrMissingActingParty, i.Configure())
	})

	t.Run("error - missing publicUrl", func(t *testing.T) {
		i := testInstance(t, AuthConfig{
			Mode:          core.ServerEngineMode,
			ActingPartyCn: "url",
		})

		assert.Equal(t, contract.ErrMissingPublicURL, i.Configure())
	})

	t.Run("error - IRMA config failure", func(t *testing.T) {
		i := testInstance(t, AuthConfig{
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

const vendorID = "urn:oid:1.3.6.1.4.1.54851.4:vendorId"

// RegisterTestDependencies registers minimal dependencies
func registerTestDependencies(t *testing.T) {
	// This makes sure instances of Auth use test instances of crypto and registry which write their data to a temp dir
	testDirectory := testIo.TestDirectory(t)
	_ = os.Setenv("NUTS_IDENTITY", vendorID)
	_ = core.NutsConfig().Load(&cobra.Command{})
	crypto.NewTestCryptoInstance(testDirectory)
	registry.NewTestRegistryInstance(testDirectory)
}

// testInstance returns an Auth instance with mock crypto and registry
func testInstance(t *testing.T, cfg AuthConfig) *Auth {
	testDirectory := testIo.TestDirectory(t)
	_ = os.Setenv("NUTS_IDENTITY", vendorID)
	_ = core.NutsConfig().Load(&cobra.Command{})

	return NewAuthInstance(cfg, crypto.NewTestCryptoInstance(testDirectory), registry.NewTestRegistryInstance(testDirectory))
}
