package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/nuts-foundation/nuts-proxy/api"
	"github.com/nuts-foundation/nuts-proxy/api/auth"
	"github.com/privacybydesign/irmago"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const HEAD_CONTENT_TYPE = "Content-Type"
const CT_JSON = "application/json"

func testContentTypeIsJson(r http.ResponseWriter, t *testing.T) {
	actualContentType := r.Header().Get(HEAD_CONTENT_TYPE)
	expectedContentType := CT_JSON
	if actualContentType != expectedContentType {
		t.Errorf("Handler returned the wrong Content-type: got %v, expected %v", actualContentType, expectedContentType)
	}
}

func TestContentType(t *testing.T) {
	req, err := http.NewRequest("POST", "/auth/contract/session", nil)

	if err != nil {
		t.Fatal(err)
	}

	testHandler := func(w http.ResponseWriter, r *http.Request) {
		testContentTypeIsJson(w, t)
	}

	handler := api.ContentTypeMiddleware(http.HandlerFunc(testHandler))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
}

func TestCreateSessionHandler(t *testing.T) {
	req, err := http.NewRequest("POST", "/auth/contract/session", nil)

	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()

	handler := http.HandlerFunc(auth.New().CreateSessionHandler)

	handler.ServeHTTP(rr, req)

	status := rr.Code
	if status != http.StatusCreated {
		t.Errorf("Handler returned the wrong status: got %v, expected %v", status, http.StatusCreated)
	}

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
}

func TestGetContract(t *testing.T) {
	router := auth.New().AuthHandler()
	ts := httptest.NewServer(router)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/contract/BehandelaarLogin")
	if err != nil {
		t.Fatal(err)
	}

	status := resp.StatusCode
	if status != http.StatusOK {
		t.Errorf("Handler returned the wrong status: got %v, expected %v", status, http.StatusOK)
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var contract auth.Contract

	fmt.Printf("body: %v", string(respBody))
	if err := json.Unmarshal(respBody, &contract); err != nil {
		t.Error("Could not unmarshal Contract response", err)
	}

	if contract.Type != "BehandelaarLogin" {
		t.Errorf("Wrong kind of contract type: got %v, expected %v", contract.Type, "BehandelaarLogin")
	}
}
