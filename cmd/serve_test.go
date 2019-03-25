package cmd

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCreateSessionHandler(t *testing.T) {
	InitIRMA()
	req, err := http.NewRequest("POST", "/auth/contract/session", nil)

	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()

	handler := http.HandlerFunc(CreateSessionHandler)

	handler.ServeHTTP(rr, req)

	status := rr.Code
	if status != http.StatusCreated {
		t.Errorf("Handler returned the wrong status: got %v, expected %v", status, http.StatusCreated)
	}
}

