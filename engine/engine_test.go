package engine

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/nuts-foundation/nuts-auth/pkg/services/irma"
	nutsCrypto "github.com/nuts-foundation/nuts-crypto/pkg"
	core "github.com/nuts-foundation/nuts-go-core"
	testIo "github.com/nuts-foundation/nuts-go-test/io"
	nutsRegistry "github.com/nuts-foundation/nuts-registry/pkg"
	"github.com/spf13/cobra"

	"github.com/nuts-foundation/nuts-auth/pkg"
	"github.com/stretchr/testify/assert"
)

func Test_initEcho(t *testing.T) {
	auth := testInstance(t, pkg.AuthConfig{IrmaConfigPath: "../testdata/irma",
		SkipAutoUpdateIrmaSchemas: true,
		ActingPartyCn:             "Foo",
		PublicUrl:                 "http://localhost:1323",
	})

	err := auth.Configure()
	assert.NoError(t, err)

	e, err := initEcho(auth)
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, irma.IrmaMountPath+"/session/123", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	response := map[string]string{}
	json.Unmarshal(rec.Body.Bytes(), &response)

	assert.Equal(t, "SESSION_UNKNOWN", response["error"])
}

const vendorID = "urn:oid:1.3.6.1.4.1.54851.4:vendorId"

func testInstance(t *testing.T, cfg pkg.AuthConfig) *pkg.Auth {
	testDirectory := testIo.TestDirectory(t)
	_ = os.Setenv("NUTS_IDENTITY", vendorID)
	_ = core.NutsConfig().Load(&cobra.Command{})
	testCrypto := nutsCrypto.NewTestCryptoInstance(testDirectory)
	nutsRegistry.NewTestRegistryInstance(testDirectory)

	return &pkg.Auth{
		Crypto: testCrypto,
		Config: cfg,
	}
}
