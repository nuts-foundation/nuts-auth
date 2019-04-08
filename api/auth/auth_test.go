package auth

import (
	"bytes"
	"encoding/json"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server/irmaserver"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type SpyIrmaService struct{}

func (s *SpyIrmaService) StartSession(request interface{}, handler irmaserver.SessionHandler) (*irma.Qr, string, error) {
	return &irma.Qr{URL: "https://api.helder.health/auth/irmaclient/123-sessionid-123", Type: irma.ActionSigning}, "", nil
}

func (s *SpyIrmaService) HandlerFunc() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello from mocked irma client handler"))
	}
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
		req, err := http.NewRequest("POST", "/auth/contract/session", bytes.NewBuffer(payload))
		if err != nil {
			t.Error("Unable to make new create session handler request", err)
		}

		return req
	}

	setupRequestRecorder := func(t *testing.T, payload []byte) (rr *httptest.ResponseRecorder) {
		t.Helper()
		rr = httptest.NewRecorder()
		req := makeRequest(t, payload)

		handler := http.HandlerFunc(API{irmaServer: &SpyIrmaService{}}.CreateSessionHandler)

		handler.ServeHTTP(rr, req)
		return
	}

	t.Run("with unknown contract type", func(t *testing.T) {
		sessionRequest := ContractSigningRequest{Type: "Unknown type", Language: "NL"}
		payload, _ := json.Marshal(sessionRequest)
		rr := setupRequestRecorder(t, payload)

		assertResponseCode(t, *rr, http.StatusBadRequest)

		message := string(rr.Body.Bytes())
		if !strings.Contains(message, "Could not find contract with type Unknown type") {
			t.Errorf("Expected different error message: %v", message)
		}
	})
	t.Run("with invalid json param", func(t *testing.T) {
		payload := []byte("invalid paload")
		rr := setupRequestRecorder(t, payload)

		assertResponseCode(t, *rr, http.StatusBadRequest)

		message := string(rr.Body.Bytes())
		if !strings.Contains(message, "Could not decode json request parameters") {
			t.Errorf("Expected different error message: %v", message)
		}

	})

	t.Run("normal execution", func(t *testing.T) {
		sessionRequest := ContractSigningRequest{Type: "BehandelaarLogin", Language: "NL"}
		payload, _ := json.Marshal(sessionRequest)
		rr := setupRequestRecorder(t, payload)

		assertResponseCode(t, *rr, http.StatusCreated)

		qr := irma.Qr{}

		if err := json.Unmarshal(rr.Body.Bytes(), &qr); err != nil {
			t.Error("Could not unmarshal json qr code response", err)
		}

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

		handler := http.HandlerFunc(New().ValidateContractHandler)

		handler.ServeHTTP(rr, req)
		return
	}
	const validContract = `{
    "signature": [
      {
        "c": "7IBqXjMivYL6SSr1v/TOpYG+3GXZMuMejsCIAtd6Xp4=",
        "A": "ljVcut65H/UTeIUHjpXEcENX1rwU0BwvaJj2Z5fTw8i3QKnzCXTsaCskA3OsdjfIU5E0xOhI8rwZnLkbd2wZ1EwrWlL0vBLqh6m8DVfUn02czr2Fx9tWY6grc2trALy0ROqM4U/pp1wBlXV7m4CcslNwFWkvO35BXECic5PHfI2LUU88DnN0jLKOHmeu60TOJqS94PxVs7Bt3A5sC7hOi7dB1DIhJJmIMyxcLSB8IP1fTucIYiK1n0rd7rYG5BgivEHGbvg27AmgrpI3Z3zbnpmycuSLN80gARx8ozIvIIS/pdw5XieTkFbxL/hJTvymbz+LVTX3eKVBQXCmXXBnYw==",
        "e_response": "Tht2LdtAmJH9kCuzNdW5PfgNqdna/iyy0xMcQVguvrmqhtMGhNE9aAZYL/BZlcFikz0xECRIkZXsLuKHmo7+",
        "v_response": "BqryxHSYLIax24I3ZT2OSXQjab8zY8I19qIUx2m7cooEjlkFBQlJxR76y48MMNt6CExMxiZaw5ygEK7sQQlMyDv4BcIpCHxn9Iu8ZuHM4DqzDMxNed2iPyqiVjjxf3uDlY/aJ0dYKLe0oYZGQ11KPAV0uz5uGqEQN9Q8kdE7ZzxPyEiUZX9HkJJQ0HB4UkKoz3jbM51DdpW4V9dmxQaO/gSP2sUWfDrUkMnfBuAdImyQ7y4g8ZWYfNNCvdUvaaWuqo27X9e9DlgVVfbWf/tUsL0EemkMW4XtB8ql371qys2HRoNxAm6uAVzZrn1EHzuPSWXLsSluUYO1JS9fEq+5EZSzSqHPuqqmxmKMU2jAe3PYtZJphp0hFxinOARTspParaN3a18Rvw68iC5gdfK6+9qZlYeRSrOfU4IvEKugeOKatcRD46tUbGO+hiYblwSInvzvRYAXx+TT2rXTtTk6ez5wK2zgajzIzSfSXHTvQTjXEd+1gSIFtuvyw8yzRqEEXnVUAyly54uE4DwuedDsQEk=",
        "a_responses": {
          "0": "kd6cCLk/IQ52zyVgJu9M9DMYiGwEQhSB6Rj80Asm55LAqsOj0AYb+LGWpf/RiSaz/vJEbfUBbJjZqBGjgbLUTkmzaht9QiXg7Ro="
        },
        "a_disclosed": {
          "1": "AwAJ8gAaAABH2jklUts5iBWSlKLhMjvi",
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
    "nonce": "pGW5aB1YNp8cADoDa2KXtQ==",
    "context": "AQ==",
    "message": "NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan Helder om uit zijn/haar naam het nuts netwerk te bevragen. Deze toestemming is geldig van Wednesday, 03-Apr-19 16:36:06 CEST tot Wednesday, 03-Apr-19 17:36:06 CEST.",
    "timestamp": {
      "Time": 1554302366,
      "ServerUrl": "https://metrics.privacybydesign.foundation/atum",
      "Sig": {
        "Alg": "ed25519",
        "Data": "7lX0cWof1dnkccBZ4QA7vz4W1JOxkPhxhj9ldzN2fuDCywR8Uk+WxPt5PuT8Rl5GO1uchky8BxKfYSi6RCfhAQ==",
        "PublicKey": "e/nMAJF7nwrvNZRpuJljNpRx+CsT7caaXyn9OX683R8="
      }
    }
}
	`
	const invalidContract = `
    { "this datas": "smellz bad"}
	`
	type ValidationResult struct { ValidationResult string `json:"validation_result"` }
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
