package auth

import (
	"bytes"
	"encoding/json"
	irma "github.com/privacybydesign/irmago"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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

		handler := http.HandlerFunc(New().CreateSessionHandler)

		handler.ServeHTTP(rr, req)
		return
	}

	assertResponseCode := func(t *testing.T, rr httptest.ResponseRecorder, expectedCode int) {
		t.Helper()
		status := rr.Code
		if status != expectedCode {
			t.Errorf("Handler returned the wrong status: got %v, expected %v", status, expectedCode)
		}
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

func TestGetContract(t *testing.T) {
	t.Run("happy flow", func(t *testing.T) {
		router := New().AuthHandler()
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
