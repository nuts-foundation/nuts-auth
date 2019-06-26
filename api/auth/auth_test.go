package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/bouk/monkey"
	"github.com/nuts-foundation/nuts-auth/auth"
	"github.com/nuts-foundation/nuts-auth/configuration"
	"github.com/nuts-foundation/nuts-auth/pkg"
	"github.com/nuts-foundation/nuts-auth/testdata"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/irmaserver"
	"github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	irma "github.com/privacybydesign/irmago"
)

type MockValidator struct{}

func (v MockValidator) ValidateContract(b64EncodedContract string, format pkg.ContractFormat, actingPartyCN string) (*pkg.ValidationResponse, error) {
	if format == pkg.IrmaFormat {
		contract, err := base64.StdEncoding.DecodeString(b64EncodedContract)
		if err != nil {
			logrus.Error("Could not base64 decode contract_string")
			return nil, err
		}
		signedContract, err := pkg.ParseIrmaContract(string(contract))
		if err != nil {
			return nil, err
		}

		return signedContract.Validate(actingPartyCN)
	}
	return nil, errors.New("unknown contract format. Currently supported formats: IRMA")
}

func (MockValidator) ValidateJwt(string, string) (*pkg.ValidationResponse, error) {
	return nil, nil
}

func (v MockValidator) SessionStatus(id pkg.SessionId) *pkg.SessionStatusResult {
	if id == "known_token" {
		return &pkg.SessionStatusResult{
			SessionResult: server.SessionResult{Status: server.StatusInitialized},
		}
	}
	return nil
}
func (v MockValidator) StartSession(request interface{}, handler irmaserver.SessionHandler) (*irma.Qr, string, error) {
	return &irma.Qr{URL: "https://api.helder.health/auth/irmaclient/123-session-ref-123", Type: irma.ActionSigning}, "abc-sessionid-abc", nil
}

func assertResponseCode(t *testing.T, rr httptest.ResponseRecorder, expectedCode int) {
	t.Helper()
	status := rr.Code
	if status != expectedCode {
		t.Errorf("Handler returned the wrong status: got %v, expected %v", status, expectedCode)
	}
}

func TestValidateContract(t *testing.T) {
	makeRequest := func(t *testing.T, payload []byte) *http.Request {
		t.Helper()
		req, err := http.NewRequest("POST", "/auth/contract/validate", bytes.NewBuffer(payload))
		if err != nil {
			t.Error("Unable to make validate contract request", err)
		}

		return req
	}

	setupRequestRecorder := func(t *testing.T, payload []byte) (rr *httptest.ResponseRecorder) {
		t.Helper()
		rr = httptest.NewRecorder()
		req := makeRequest(t, payload)

		handlerFunc := New(&configuration.NutsProxyConfiguration{HttpAddress: "https://helder.health"}, MockValidator{}, MockValidator{})

		handler := http.HandlerFunc(handlerFunc.ValidateContractHandler)

		handler.ServeHTTP(rr, req)
		return
	}
	type ValidationResult struct {
		ValidationResult string `json:"validation_result"`
	}
	_ = configuration.Initialize("../../testdata", "testconfig")

	t.Run("test a valid contract", func(t *testing.T) {
		// mock time.Now() so we can validate the contract
		location, _ := time.LoadLocation("Europe/Amsterdam")
		contractDate := time.Date(2019, time.April, 26, 11, 46, 00, 0, location)
		patch := monkey.Patch(time.Now, func() time.Time { return contractDate })
		defer patch.Unpatch()

		rr := setupRequestRecorder(t, []byte(testdata.ConstructValidationContract(testdata.ValidIrmaContract, "Helder")))
		assertResponseCode(t, *rr, http.StatusOK)

		var result ValidationResult
		if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
			t.Error("Could not unmarshal validation result from response", err)
		}

		expected := "VALID"
		if result.ValidationResult != expected {
			t.Errorf("Expected different validation result: expected '%v', got '%v'", expected, result.ValidationResult)
		}
	})

	t.Run("test an invalid contract", func(t *testing.T) {
		// FIXME
		t.Skip("This seems to fail but unsure why")
		rr := setupRequestRecorder(t, []byte(testdata.ConstructValidationContract(testdata.InvalidContract, "Helder")))
		assertResponseCode(t, *rr, http.StatusOK)

		var result ValidationResult
		if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
			t.Error("Could not unmarshal validation result from response", err)
		}
		expected := "INVALID"

		if result.ValidationResult != expected {
			t.Errorf("Expected different validation result: expected '%v' got'%v'", expected, result.ValidationResult)
		}
	})

	t.Run("test a malformed contract", func(t *testing.T) {
		rr := setupRequestRecorder(t, []byte("malformed contract"))
		assertResponseCode(t, *rr, http.StatusBadRequest)
	})

	t.Run("validate an empty signed message", func(t *testing.T) {
		// FIXME
		t.Skip("This seems to fail but unsure why")
		msg := &irma.SignedMessage{}
		_, status, _ := msg.Verify(&irma.Configuration{}, nil)
		if status != irma.ProofStatusInvalid {
			t.Error("An empty signed message should be invalid")
		}
	})
}

func TestGetContract(t *testing.T) {
	t.Run("a known contracts returns the contract", func(t *testing.T) {
		api := API{configuration: &configuration.NutsProxyConfiguration{HttpAddress: "https://helder.health", ActingPartyCN: "Helder"}, contractValidator: MockValidator{}}
		router := api.Handler()
		ts := httptest.NewServer(router)
		defer ts.Close()

		resp, body := testRequest(t, ts, "GET", "/contract/BehandelaarLogin", nil)

		status := resp.StatusCode
		if status != http.StatusOK {
			t.Errorf("Handler returned the wrong status: got %v, expected %v", status, http.StatusOK)
		}

		var contract auth.Contract

		if err := json.Unmarshal([]byte(body), &contract); err != nil {
			t.Error("Could not unmarshal Contract response", err)
		}

		if contract.Type != "BehandelaarLogin" {
			t.Errorf("Wrong kind of contract type: got %v, expected %v", contract.Type, "BehandelaarLogin")
		}
	})

	t.Run("an unknown contract results a 404", func(t *testing.T) {
		api := API{configuration: &configuration.NutsProxyConfiguration{HttpAddress: "https://helder.health", ActingPartyCN: "Helder"}, contractValidator: MockValidator{}}
		router := api.Handler()
		ts := httptest.NewServer(router)
		defer ts.Close()

		expected := http.StatusNotFound
		resp, _ := testRequest(t, ts, "GET", "/contract/BehandelaarLogin?language=EN", nil)

		status := resp.StatusCode
		if status != expected {
			t.Errorf("Handler returned the wrong status: got %v, expected %v", status, expected)
		}
	})
}

func testRequest(t *testing.T, ts *httptest.Server, method, path string, body io.Reader) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, ts.URL+path, body)
	if err != nil {
		t.Fatal(err)
		return nil, ""
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
		return nil, ""
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
		return nil, ""
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	return resp, string(respBody)
}

func TestAPI_GetSessionStatus(t *testing.T) {
	api := API{configuration: &configuration.NutsProxyConfiguration{
		HttpAddress: "https://helder.health",
		ActingPartyCN: "Helder"},
		contractValidator:      MockValidator{},
		contractSessionHandler: MockValidator{},
	}
	router := api.Handler()
	ts := httptest.NewServer(router)
	defer ts.Close()

	t.Run("unknown session results in http status code 404", func(t *testing.T) {
		resp, _ := testRequest(t, ts, "GET", "/contract/session/123", nil)

		httpStatus := resp.StatusCode
		if httpStatus != http.StatusNotFound {
			t.Errorf("Handler returned the wrong httpStatus: got %v, expected %v", httpStatus, http.StatusNotFound)
		}
	})

	t.Run("when the session has started, status is PENDING", func(t *testing.T) {
		resp, body := testRequest(t, ts, "GET", "/contract/session/known_token", nil)
		httpStatus := resp.StatusCode
		if httpStatus != http.StatusOK {
			t.Errorf("Handler returned the wrong httpStatus: got %v, expected %v", httpStatus, http.StatusOK)
		}

		var status SessionStatusResult

		if err := json.Unmarshal([]byte(body), &status); err != nil {
			t.Errorf("Could not unmarshal SessionStatus response :'%v'", body)
		}

		if status.Status != "INITIALIZED" {
			t.Errorf("Wrong kind of status type: got %v, expected %v", status.Status, "INITIALIZED")
		}
	})

}
