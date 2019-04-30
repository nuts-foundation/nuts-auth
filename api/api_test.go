package api

import (
	"github.com/sirupsen/logrus"
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

	api := New(&Config{Logger:logrus.New()})
	api.router.Post("/auth/contract/session", testHandler)

	rr := httptest.NewRecorder()
	api.router.ServeHTTP(rr, req)
}
