/*
 * Nuts auth
 * Copyright (C) 2020. Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package x509

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

type CrlGetter interface {
	GetCrl(url string) (*pkix.CertificateList, error)
}

// Compiler check if HttpCrlService implements the CrlGetter
var _ CrlGetter = (*HttpCrlService)(nil)

type HttpCrlService struct {
}

// GetCrl accepts a url and will try to make a http request to that endpoint. The results will be parsed into a CertificateList.
// Note: The call is blocking. It is advisable to use this service behind a caching mechanism or use cachedHttpCrlService
func (h HttpCrlService) GetCrl(url string) (*pkix.CertificateList, error) {
	// TODO: this is a rather naive implementation of a http crl getter. It will not scale under high load and will
	// block requests when the crl endpoint is down.
	// https://github.com/nuts-foundation/nuts-auth/issues/136
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	} else if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("failed to retrieve CRL: '%s' statuscode: %s", url, resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("could not read the crl response body: %w", err)
	}
	resp.Body.Close()

	return x509.ParseCRL(body)
}

var _ CrlGetter = (*memoryCrlService)(nil)

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

var _ CrlGetter = (*cachedHttpCrlService)(nil)

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
