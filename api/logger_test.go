package api

import (
	"bytes"
	"fmt"
	"github.com/go-chi/chi/middleware"
	"github.com/sirupsen/logrus"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func getTestHandler() http.HandlerFunc {
	fn := func(rw http.ResponseWriter, req *http.Request) {
		panic("Test handler says panic")
	}
	return http.HandlerFunc(fn)
}

func TestStructuredLogger_NewLogEntry(t *testing.T) {
	// Create test HTTP server
	buf := &bytes.Buffer{}

	logrusInstance := logrus.New()
	logrusInstance.Out = buf
	logMiddleware := NewStructuredLogger(logrusInstance)
	ts := httptest.NewServer(logMiddleware(middleware.Recoverer(getTestHandler())))
	defer ts.Close()

	http.Get(fmt.Sprintf("%s/", ts.URL))

	if buf.Len() == 0 {
		t.Error("It should have logged")
	}

	lines := strings.Split(buf.String(), "\n")

	// check for 3 entries since the newline split results in 1 empty 3rd string
	if len(lines) != 3 {
		t.Errorf("Expected 2 logged lines.")
	}

	if !strings.Contains(lines[1], "Test handler says panic") {
		t.Errorf("Expected log line to contain panic message. Instead got: %s", lines[1])
	}
}
