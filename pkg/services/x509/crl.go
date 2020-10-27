package x509

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

type crlService interface {
	GetCrl(url string) (*pkix.CertificateList, error)
}

// Compiler check if HttpCrlService implements the crlService
var _ crlService = (*HttpCrlService)(nil)

type HttpCrlService struct {
}

func (h HttpCrlService) GetCrl(url string) (*pkix.CertificateList, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	} else if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("failed to retrieve CRL")
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	return x509.ParseCRL(body)
}

var _ crlService = (*memoryCrlService)(nil)

type memoryCrlService struct {
	crls map[string]*pkix.CertificateList
}

func NewMemoryCrlService() memoryCrlService {
	return memoryCrlService{
		crls: make(map[string]*pkix.CertificateList),
	}
}

func (m memoryCrlService) GetCrl(url string) (*pkix.CertificateList, error) {
	crl, ok := m.crls[url]
	if !ok {
		return nil, fmt.Errorf("unknown crl '%s'", url)
	}
	return crl, nil
}

var _ crlService = (*cachedHttpCrlService)(nil)

type cachedHttpCrlService struct {
	httpCrlService   HttpCrlService
	memoryCrlService memoryCrlService
}

func NewCachedHttpCrlService() *cachedHttpCrlService {
	return &cachedHttpCrlService{
		httpCrlService:   HttpCrlService{},
		memoryCrlService: NewMemoryCrlService(),
	}
}

func (c *cachedHttpCrlService) GetCrl(url string) (crl *pkix.CertificateList, err error) {
	expiredOrErr := true

	crl, err = c.memoryCrlService.GetCrl(url)
	if err == nil {
		expiredOrErr = crl.HasExpired(time.Now())
	}

	if expiredOrErr {
		crl, err = c.httpCrlService.GetCrl(url)
		if err == nil {
			c.memoryCrlService.crls[url] = crl
		}
	}
	return
}
