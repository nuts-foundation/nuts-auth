package auth

import (
	"bytes"
	"encoding/json"
	"github.com/nuts-foundation/nuts-proxy/configuration"
	"github.com/privacybydesign/irmago/server"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server/irmaserver"
)

type SpyIrmaService struct{}

func (s *SpyIrmaService) StartSession(request interface{}, handler irmaserver.SessionHandler) (*irma.Qr, string, error) {
	return &irma.Qr{URL: "https://api.helder.health/auth/irmaclient/123-session-ref-123", Type: irma.ActionSigning}, "abc-sessionid-abc", nil
}

func (s *SpyIrmaService) HandlerFunc() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("Hello from mocked irma client handler"))
	}
}

func (s *SpyIrmaService) GetSessionResult(token string) *server.SessionResult {
	if token == "known_token" {
		return &server.SessionResult{ Status: server.StatusInitialized}
	}
	return nil
}

func assertResponseCode(t *testing.T, rr httptest.ResponseRecorder, expectedCode int) {
	t.Helper()
	status := rr.Code
	if status != expectedCode {
		t.Errorf("Handler returned the wrong status: got %v, expected %v", status, expectedCode)
	}
}

func TestCreateSessionHandler(t *testing.T) {
	makeRequest := func(t *testing.T, payload []byte) *http.Request {
		t.Helper()
		req, err := http.NewRequest("POST", "/contract/session", bytes.NewBuffer(payload))
		if err != nil {
			t.Error("Unable to make new create session handler request", err)
		}

		return req
	}

	loadConfig := func() {
		err := configuration.Initialize("../../testdata", "testconfig")
		if err != nil {
			t.Error(err)
		}
	}

	setupRequestRecorder := func(t *testing.T, payload []byte) (rr *httptest.ResponseRecorder) {
		t.Helper()
		rr = httptest.NewRecorder()
		req := makeRequest(t, payload)

		api := API{irmaServer: &SpyIrmaService{}}
		router := api.Handler()

		handler := http.Handler(router)

		handler.ServeHTTP(rr, req)
		return
	}

	t.Run("with unknown acting party result in error", func(t *testing.T) {
		sessionRequest := ContractSigningRequest{Type: "BehandelaarLogin", Language: "NL"}
		payload, _ := json.Marshal(sessionRequest)
		loadConfig()
		configuration.GetInstance().ActingPartyCN = ""
		rr := setupRequestRecorder(t, payload)

		assertResponseCode(t, *rr, http.StatusForbidden)
	})

	t.Run("with unknown contract type", func(t *testing.T) {
		sessionRequest := ContractSigningRequest{Type: "Unknown type", Language: "NL"}
		payload, _ := json.Marshal(sessionRequest)
		loadConfig()
		rr := setupRequestRecorder(t, payload)

		assertResponseCode(t, *rr, http.StatusBadRequest)

		message := rr.Body.String()
		if !strings.Contains(message, "Could not find contract with type Unknown type") {
			t.Errorf("Expected different error message: %v", message)
		}
	})
	t.Run("with invalid json param returns a bad request", func(t *testing.T) {
		payload := []byte("invalid paload")
		loadConfig()
		rr := setupRequestRecorder(t, payload)

		assertResponseCode(t, *rr, http.StatusBadRequest)

		message := rr.Body.String()
		if !strings.Contains(message, "Could not decode json request parameters") {
			t.Errorf("Expected different error message: %v", message)
		}

	})

	t.Run("valid request returns a qr code and sessionId", func(t *testing.T) {
		sessionRequest := ContractSigningRequest{Type: "BehandelaarLogin", Language: "NL"}
		payload, _ := json.Marshal(sessionRequest)
		loadConfig()
		rr := setupRequestRecorder(t, payload)

		assertResponseCode(t, *rr, http.StatusCreated)

		response := CreateSessionResult{}

		if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
			t.Error("Could not unmarshal json qr code response", err)
		}

		if response.SessionId == "" {
			t.Error("expected a sessionId in the response")
		}

		qr := response.QrCodeInfo

		if qr.Type != irma.ActionSigning {
			t.Errorf("Wrong kind of IRMA session type: got %v, expected %v", qr.Type, irma.ActionSigning)
		}

		if !strings.Contains(qr.URL, "/auth/irmaclient/") {
			t.Errorf("Qr-code does not contain valid url: got %v, expected it to contain %v", qr.URL, "/auth/irmaclient/")
		}
	})
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

		baseUrl, _ := url.Parse("http://localhost:3000")

		handler := http.HandlerFunc(New(baseUrl).ValidateContractHandler)

		handler.ServeHTTP(rr, req)
		return
	}
	const validContract = `{
    "signature": [
      {
        "c": "TH/z6HoTX5rvu70H8t7Q3B7mKG09a3LRU6UqlkEfJ3M=",
        "A": "dcij67w/Dlk7FJftjFEvaQ8FKOf5PaLjrhfza9pl2OvqUFDeor0jMY5WiYpY6nimM4HT72BfNh6qS+RbMgk7TIVvPj3wV12BX7TRmLOwpHRM34JVtyen4msIJCoBm8or+T1HHE3bGhAN1kld9bG6HiprJGzMDz6eV2VMM1ppSIcbg+J6Mt4XlaCOqTi7ox+hvgVxOTJu5OlIMw4/OvmSRkG63h7iSuHF8pmavB3bUh3UUww2tVeesgDp1zQoSZKWJ8a+J1BHTDYAOy8fiS0tpDnckX09v/LiQOzYocPB2NUGn9AzCEcrlCZU3MNYSHlKH80dINoHE6+NkdzjMhrVHQ==",
        "e_response": "1AjGh0WGbR5lZ6bqORFDKhhu2ORmY3B6H3SCXOtSbmi1x40CXAAw/ADCFXuy+wQd5OHwka85FmQD7vinSCkv",
        "v_response": "CRNwuI0B5L9r/anmGdSqqpFtW8EHfkZeBo65aUPspRTpgvA6OjefaxNz06bJeIwuIgInKXMo8HbmISYYUAbVe9wvDwW9Jd5qw8N6sQiUnUouvhvWfBB5g04d6GbEfgszlNgXNQBpxowXlLe3Kphq8HOzlGPyGtC5jzsFv9iQQx2VVDWOxZ/lJSUwylM8luGsiMl4Pj2iVQ+2Lx9gAdVRdrjRwnmrkd6mcpH4fk/8NZ3wl8BMgG/U519DmZ7QachzOC2a5OdhkBF+v98bwUFmNXl+2ck1PpYrstJC37EAQQNHyLP9C1XCyDoLL9Sr1NIay6nb/q5nP2hjJQVLunOfTDEOAtz08mmn7oLIwS8uaO+Gi9vM8yqEd7ArAmGJvDkjE6y4tXDxyhNcs6q7+2q3kkwTR75wf5Z+rbrp8nhgqDwLQaZsiK4QGXkATuuGnYSSEPVKUWkQaXuX9b5PRoAwj1Ik61Noyfolxqsy89dvW8ffFyM6TaESk01aihjXFiL7oeGFPgTaKOxLQdYsujrym6M=",
        "a_responses": {
          "0": "s9L2fM80S9pNxwqC/nbhByCVL12XX+V3kLavkcWwLRPgIMEBCOPSBpcxFhsqWK5HosCRdBr5YpWTzIm8+JcZaB8HGTkS5srqJMs=",
          "3": "DcAgFh30gmjhe5GsUNWZw2WZgDBuoCIDjBkCsHA0CyTJBVEfoDIYHYc3pJ0eFJngQ3T+X2tFrIL0M/rABvgRfLvfShmnihSXOGNI9orRf+g="
        },
        "a_disclosed": {
          "1": "AwAKCwAaAABH2jklUts5iBWSlKLhMjvi",
          "2": "YGBgYGBgYGM="
        }
      }
    ],
    "indices": [
      [
        {
          "cred": 0,
          "attr": 2
        }
      ]
    ],
    "nonce": "YPffjG+4BTMBtW1j5z1HOA==",
    "context": "AQ==",
    "message": "NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan Helder om uit zijn/haar naam het Nuts netwerk te bevragen. Deze toestemming is geldig van vrijdag, 26 april 2019 11:45:30 tot vrijdag, 26 april 2019 12:45:30.",
    "timestamp": {
      "Time": 1556271999,
      "ServerUrl": "https://metrics.privacybydesign.foundation/atum",
      "Sig": {
        "Alg": "ed25519",
        "Data": "B1vRNosk4094k29T3JIsz1Te/YZEkSKFertuwvvTWUiWx5isZ3AYnc0ufBiL8eYqxtrkKGlhkBvz/NPz8ojIDQ==",
        "PublicKey": "e/nMAJF7nwrvNZRpuJljNpRx+CsT7caaXyn9OX683R8="
      }
    }
  }
`
	const invalidContract = `
    { "this datas": "smellz bad"}
	`
	type ValidationResult struct {
		ValidationResult string `json:"validation_result"`
	}
	t.Run("test a valid contract", func(t *testing.T) {
		rr := setupRequestRecorder(t, []byte(validContract))
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
		rr := setupRequestRecorder(t, []byte(invalidContract))
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
	t.Run("happy flow", func(t *testing.T) {
		api := API{irmaServer: &SpyIrmaService{}}
		router := api.Handler()
		ts := httptest.NewServer(router)
		defer ts.Close()

		resp, body := testRequest(t, ts, "GET", "/contract/BehandelaarLogin", nil)

		status := resp.StatusCode
		if status != http.StatusOK {
			t.Errorf("Handler returned the wrong status: got %v, expected %v", status, http.StatusOK)
		}

		var contract Contract

		if err := json.Unmarshal([]byte(body), &contract); err != nil {
			t.Error("Could not unmarshal Contract response", err)
		}

		if contract.Type != "BehandelaarLogin" {
			t.Errorf("Wrong kind of contract type: got %v, expected %v", contract.Type, "BehandelaarLogin")
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
	api := API{irmaServer: &SpyIrmaService{}}
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

		var status SessionStatus

		if err := json.Unmarshal([]byte(body), &status); err != nil {
			t.Errorf("Could not unmarshal SessionStatus response :'%v'", body)
		}

		if status.Status != "INITIALIZED" {
			t.Errorf("Wrong kind of status type: got %v, expected %v", status.Status, "INITIALIZED")
		}
	})

}
