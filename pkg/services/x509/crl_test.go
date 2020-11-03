package x509

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

type mockCrlService struct {
	mCrls memoryCrlService
}

func NewMockCrlService(urls []string) (*mockCrlService, error) {
	crls := map[string]*pkix.CertificateList{}
	for _, rawUrl := range urls {
		url, err := url.Parse(rawUrl)
		if err != nil {
			return nil, err
		}
		certName := url.Path[strings.LastIndex(url.Path, "/")+1:]

		rawCrl, err := ioutil.ReadFile(fmt.Sprintf("../../../testdata/certs/%s", certName))
		if err != nil {
			return nil, err
		}
		crl, err := x509.ParseCRL(rawCrl)
		if err != nil {
			return nil, err
		}
		crls[rawUrl] = crl
	}
	return &mockCrlService{mCrls: memoryCrlService{crls: crls}}, nil
}

func (m mockCrlService) GetCrl(url string) (*pkix.CertificateList, error) {
	return m.mCrls.GetCrl(url)
}

func Test_cachedHttpCrlService_GetCrl(t *testing.T) {
	var crl []byte
	serverHits := 0

	crlServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		t.Log("crl request received")
		serverHits = serverHits + 1
		writer.Write(crl)
	}))
	defer crlServer.Close()

	rootCert, rootCertKey, err := createTestRootCert()
	if !assert.NoError(t, err) {
		return
	}

	intermediateCert, _, err := createIntermediateCertWithCrl(rootCert, rootCertKey, crlServer.URL)
	if !assert.NoError(t, err) {
		return
	}

	crl, err = createCrl(nil, rootCert, rootCertKey, []*x509.Certificate{intermediateCert})
	if !assert.NoError(t, err) {
		return
	}

	t.Run("ok - it loads the crl first time, not the second", func(t *testing.T) {
		oldHits := serverHits
		chcs := NewCachedHttpCrlService()
		expectedCrl, err := x509.ParseCRL(crl)
		if !assert.NoError(t, err) {
			return
		}

		// first request
		foundCrl, err := chcs.GetCrl(crlServer.URL)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, expectedCrl, foundCrl)
		assert.Equal(t, oldHits+1, serverHits)

		// second request
		foundCrl, err = chcs.GetCrl(crlServer.URL)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, expectedCrl, foundCrl)
		// request should be cached
		assert.Equal(t, oldHits+1, serverHits)

	})
}
