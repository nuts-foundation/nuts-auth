package engine

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nuts-foundation/nuts-auth/pkg/services/irma"

	"github.com/nuts-foundation/nuts-auth/pkg"
	"github.com/stretchr/testify/assert"
)

func Test_initEcho(t *testing.T) {
	// This test checks the IRMA mount by requesting a unknown session status.
	auth := &pkg.Auth{
		Config: pkg.AuthConfig{IrmaConfigPath: "../testdata/irma",
			SkipAutoUpdateIrmaSchemas: true,
			ActingPartyCn:             "Foo",
			PublicUrl:                 "http://localhost:1323",
		},
	}
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
