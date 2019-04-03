package cmd

import (
	"github.com/nuts-foundation/nuts-proxy/api"
	"net/http"
	"net/http/httptest"
	"testing"
)

const HeadContentType = "Content-Type"
const ContentTypeJson = "application/json"

func testContentTypeIsJson(r http.ResponseWriter, t *testing.T) {
	actualContentType := r.Header().Get(HeadContentType)
	expectedContentType := ContentTypeJson
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

	handler := api.ContentTypeMiddlewareFn("application/json")(http.HandlerFunc(testHandler))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
}
