package x509

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

func createTestCert(parent, template *x509.Certificate, pubKey *rsa.PublicKey, caKey *rsa.PrivateKey) (*x509.Certificate, error) {
	if parent == nil {
		parent = template
	}

	derCert, err := x509.CreateCertificate(rand.Reader, template, parent, pubKey, caKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(derCert)
}

func createTestRootCert() (*x509.Certificate, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-10 * time.Second),
		NotAfter:     time.Now().Add(24 * time.Hour),
		Subject: pkix.Name{
			Country:      []string{"NL"},
			Organization: []string{"Nuts"},
			CommonName:   "Nuts Test - Root CA",
		},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		MaxPathLen:            2,
	}

	cert, err := createTestCert(nil, template, &priv.PublicKey, priv)
	return cert, priv, err
}

func createIntermediateCert(parent *x509.Certificate, caKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-10 * time.Second),
		NotAfter:     time.Now().Add(24 * time.Hour),
		Subject: pkix.Name{
			Country:      []string{"NL"},
			Organization: []string{"Nuts"},
			CommonName:   "Nuts Test - Intermediate CA",
		},
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		MaxPathLen:            2,
		MaxPathLenZero:        false,
	}
	cert, err := createTestCert(parent, template, &priv.PublicKey, caKey)
	return cert, priv, err
}
func createLeafCert(parent *x509.Certificate, caKey *rsa.PrivateKey) (*x509.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, nil
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		Subject: pkix.Name{
			Country:    []string{"NL"},
			CommonName: "Henk de Vries",
		},
	}
	return createTestCert(parent, template, &priv.PublicKey, caKey)
}
