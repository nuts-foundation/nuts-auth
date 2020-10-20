package x509

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-auth/pkg/contract"
)

func TestNewJwtX509Validator(t *testing.T) {
	rootCert, rootCertKey, err := createTestRootCert()
	if !assert.NoError(t, err) {
		return
	}

	intermediateCert, intermediateCerKey, err := createIntermediateCert(rootCert, rootCertKey)
	if !assert.NoError(t, err) {
		return
	}

	leafCert, err := createLeafCert(intermediateCert, intermediateCerKey)
	if !assert.NoError(t, err) {
		return
	}

	t.Run("validator with only a root", func(t *testing.T) {
		validator := NewJwtX509Validator([]*x509.Certificate{rootCert}, nil, &contract.TemplateStore{})
		assert.NotNil(t, validator)

		t.Run("ok - leaf and intermediate in token", func(t *testing.T) {
			token := &JwtX509Token{chain: []*x509.Certificate{leafCert, intermediateCert}}
			leaf, chain, err := validator.verifyCertChain(token)
			if !assert.NoError(t, err) {
				return
			}
			assert.Equal(t, leafCert, leaf)
			assert.Len(t, chain[0], 3)
		})

		t.Run("nok - intermediate missing from token", func(t *testing.T) {
			token := &JwtX509Token{chain: []*x509.Certificate{leafCert}}
			leaf, chain, err := validator.verifyCertChain(token)
			if assert.Error(t, err) {
				assert.Equal(t, err.Error(), "unable to verify certificate chain: x509: certificate signed by unknown authority")
			}
			assert.Nil(t, leaf)
			assert.Nil(t, chain)
		})

		t.Run("nok - complete chain in token, but not part of roots", func(t *testing.T) {
			otherRootCert, _, _ := createTestRootCert()
			validator := NewJwtX509Validator([]*x509.Certificate{otherRootCert}, nil, &contract.TemplateStore{})
			token := &JwtX509Token{chain: []*x509.Certificate{leafCert, intermediateCert, rootCert}}
			_, _, err := validator.verifyCertChain(token)
			assert.Error(t, err)
			assert.EqualError(t, err, "unable to verify certificate chain: x509: certificate signed by unknown authority (possibly because of \"crypto/rsa: verification error\" while trying to verify candidate authority certificate \"Nuts Test - Root CA\")")
		})

	})

	t.Run("nok - root is not a root", func(t *testing.T) {
		validator := NewJwtX509Validator([]*x509.Certificate{intermediateCert}, nil, &contract.TemplateStore{})
		token := &JwtX509Token{chain: []*x509.Certificate{leafCert}}
		leaf, chain, err := validator.verifyCertChain(token)
		assert.Nil(t, leaf)
		assert.Nil(t, chain)
		if assert.Error(t, err) {
			assert.Equal(t, err.Error(), "certificate is not a root CA")
		}
	})

	t.Run("validator with root and intermediates", func(t *testing.T) {
		validator := NewJwtX509Validator([]*x509.Certificate{rootCert}, []*x509.Certificate{intermediateCert}, &contract.TemplateStore{})
		assert.NotNil(t, validator)

		t.Run("ok - valid chain", func(t *testing.T) {
			token := &JwtX509Token{chain: []*x509.Certificate{leafCert}}
			leaf, chain, err := validator.verifyCertChain(token)
			if !assert.NoError(t, err) {
				return
			}
			assert.Equal(t, leafCert, leaf)
			assert.Len(t, chain[0], 3)
		})

		t.Run("nok - token without leaf cert", func(t *testing.T) {
			token := &JwtX509Token{chain: []*x509.Certificate{}}
			leaf, chain, err := validator.verifyCertChain(token)
			if assert.Error(t, err) {
				assert.Equal(t, err.Error(), "token does not have a certificate")
			}
			assert.Nil(t, leaf)
			assert.Nil(t, chain)
		})

	})
	t.Run("nok - validator without roots", func(t *testing.T) {
		validator := NewJwtX509Validator(nil, []*x509.Certificate{rootCert, intermediateCert}, &contract.TemplateStore{})
		token := &JwtX509Token{chain: []*x509.Certificate{leafCert, intermediateCert}}
		_, _, err := validator.verifyCertChain(token)
		if assert.Error(t, err) {
			assert.Equal(t, err.Error(), "unable to verify certificate chain: x509: certificate signed by unknown authority")
		}
	})
}

func TestJwtX509Validator_Parse(t *testing.T) {
}

func TestJwtX509Validator_SubjectAltNameOtherName(t *testing.T) {
	t.Run("ok - parse an UZI signature", func(t *testing.T) {
		// prepare token with leaf cert from uzi card:
		b64EncodedCert := "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\n"
		rawCert, err := base64.StdEncoding.DecodeString(b64EncodedCert)
		if !assert.NoError(t, err) {
			return
		}
		leaf, err := x509.ParseCertificate(rawCert)
		if !assert.NoError(t, err) {
			return
		}
		token := JwtX509Token{
			chain: []*x509.Certificate{leaf},
		}

		san, err := token.SubjectAltNameOtherName()
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, "2.16.528.1.1007.99.218-1-900021219-N-90000382-00.000-00000000", san)
	})

	t.Run("ok - no san in cert", func(t *testing.T) {
		rootCert, _, err := createTestRootCert()
		if !assert.NoError(t, err) {
			return
		}
		token := JwtX509Token{
			chain: []*x509.Certificate{rootCert},
		}

		san, err := token.SubjectAltNameOtherName()
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, "", san)
	})

	t.Run("ok - own certificate", func(t *testing.T) {
		// Create the extension
		otherNameValue, err := asn1.Marshal("foo:bar")
		othernameExt, err := asn1.Marshal(generalNames{
			OtherName: otherName{
				OID:   asn1.ObjectIdentifier{2, 5, 5, 5},
				Value: asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: otherNameValue},
			}})
		if !assert.NoError(t, err) {
			return
		}

		// assemble the certificate template with the extension
		template := &x509.Certificate{
			SerialNumber:    big.NewInt(1),
			NotBefore:       time.Now().Add(-10 * time.Second),
			NotAfter:        time.Now().Add(24 * time.Hour),
			ExtraExtensions: []pkix.Extension{{Id: subjectAltNameID, Value: othernameExt}},
		}

		// generate a private key and create the self signed certificate
		priv, err := rsa.GenerateKey(rand.Reader, 1024)
		if !assert.NoError(t, err) {
			return
		}
		cert, err := createTestCert(nil, template, &priv.PublicKey, priv)

		token := JwtX509Token{chain: []*x509.Certificate{cert}}
		san, err := token.SubjectAltNameOtherName()
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, "foo:bar", san)

	})
}
