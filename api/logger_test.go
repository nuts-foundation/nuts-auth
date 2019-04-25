package api

import (
	"bytes"
	"fmt"
	"github.com/sirupsen/logrus"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func getTestHandler() http.HandlerFunc {
	fn := func(rw http.ResponseWriter, req *http.Request) {
		rw.Write([]byte("Hello Nuts!!"))
	}
	return http.HandlerFunc(fn)
}

func TestStructuredLogger_NewLogEntry(t *testing.T) {
	// Create test HTTP server
	buf := &bytes.Buffer{}

	logrusInstance := logrus.New()
	logrusInstance.Out = buf
	logMiddleware := NewStructuredLogger(logrusInstance)
	ts := httptest.NewServer(logMiddleware(getTestHandler()))
	defer ts.Close()

	http.Get(fmt.Sprintf("%s/", ts.URL))

	if buf.Len() == 0 {
		t.Error("It should have logged")
	}

	if strings.Count(buf.String(), "\n") != 2 {
		t.Errorf("Expecetd 2 logged lines.")
	}
}
