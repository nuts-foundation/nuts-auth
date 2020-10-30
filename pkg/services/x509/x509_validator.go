package x509

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
)

// JwtX509Token contains a parsed JWT signed with a x509 certificate.
type JwtX509Token struct {
	chain  []*x509.Certificate
	token  jwt.Token
	raw    string
	sigAlg jwa.SignatureAlgorithm
}

// JwtX509Validator contains all logic to parse and verify a JwtX509Token.
type JwtX509Validator struct {
	roots              []*x509.Certificate
	intermediates      []*x509.Certificate
	allowedSigningAlgs []jwa.SignatureAlgorithm
	crls               CrlGetter
}

// generalNames defines the asn1 data structure of the generalNames as defined in rfc5280#section-4.2.1.6
type generalNames struct {
	OtherName otherName `asn1:"tag:0"`
}

// otherName defines the asn1 data structure of the othername as defined in rfc5280#section-4.2.1.6
type otherName struct {
	OID   asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"tag:0"`
}

// subjectAltNameID is the object identifier of the subjectAltName (id-ce 17)
var subjectAltNameID = asn1.ObjectIdentifier{2, 5, 29, 17}

// SubjectAltNameOtherNames extracts the SANs as string from the certificate which was used to sign the Jwt.
func (j JwtX509Token) SubjectAltNameOtherNames() ([]string, error) {
	leaf := j.chain[0]
	result := []string{}
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(subjectAltNameID) {
			if len(ext.Value) == 0 {
				continue
			}

			var otherNames generalNames
			if _, err := asn1.Unmarshal(ext.Value, &otherNames); err != nil {
				return nil, err
			}
			var otherNameStr string
			if _, err := asn1.Unmarshal(otherNames.OtherName.Value.Bytes, &otherNameStr); err != nil {
				return nil, err
			}
			result = append(result, otherNameStr)
		}
	}
	return result, nil
}

// NewJwtX509Validator creates a new NewJwtX509Validator.
// It accepts root and intermediate certificates to validate the chain.
// It accepts a list of valid signature algorithms
// It accepts a CRL getter
func NewJwtX509Validator(roots, intermediates []*x509.Certificate, allowedSigAlgs []jwa.SignatureAlgorithm, crls CrlGetter) *JwtX509Validator {
	return &JwtX509Validator{
		roots:              roots,
		intermediates:      intermediates,
		allowedSigningAlgs: allowedSigAlgs,
		crls:               crls,
	}
}

// Parse attempts to parse a string as a jws. It checks if the x5c header contains at least 1 certificate.
// The signature should be signed with the private key of the leaf certificate.
// No other validations are performed. Call Verify to verify the auth token.
func (validator JwtX509Validator) Parse(rawAuthToken string) (*JwtX509Token, error) {
	// check the cert chain in the jwt
	rawHeader, _, _, err := jws.SplitCompact(bytes.NewReader([]byte(rawAuthToken)))
	if err != nil {
		return nil, fmt.Errorf("the jwt should contain out of 3 parts: %w", err)
	}

	headers := jws.NewHeaders()
	headerStr, _ := base64.RawURLEncoding.DecodeString(string(rawHeader))
	if err = json.Unmarshal(headerStr, headers); err != nil {
		return nil, fmt.Errorf("could not parse jwt headers: %w", err)
	}

	certsFromHeader := headers.X509CertChain()
	if len(certsFromHeader) == 0 {
		return nil, fmt.Errorf("the jwt x5c field should contain at least 1 certificate")
	}

	chain, err := validator.parseBase64EncodedCertList(certsFromHeader)
	if err != nil {
		return nil, fmt.Errorf("could not parse certificates from headers: %w", err)
	}

	certUsedForSigning := chain[0]

	payload, err := jws.Verify([]byte(rawAuthToken), headers.Algorithm(), certUsedForSigning.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("could not verify jwt signature: %w", err)
	}

	parsedJwt := jwt.New()
	if err := json.Unmarshal(payload, &parsedJwt); err != nil {
		return nil, fmt.Errorf("could not parse jwt payload: %w", err)
	}

	return &JwtX509Token{
		chain:  chain,
		token:  parsedJwt,
		raw:    rawAuthToken,
		sigAlg: headers.Algorithm(),
	}, nil
}

// parseBase64EncodedCertList makes it convenient to parse an array of base64 certificate into x509.Certificates
func (validator JwtX509Validator) parseBase64EncodedCertList(certsFromHeader []string) ([]*x509.Certificate, error) {
	// Parse all the certificates from the header into a chain
	chain := []*x509.Certificate{}

	for _, certStr := range certsFromHeader {
		rawCert, err := base64.StdEncoding.Strict().DecodeString(certStr)
		if err != nil {
			return nil, fmt.Errorf("could not base64 decode certificate: %w", err)
		}
		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			return nil, fmt.Errorf("could not parse certificate: %w", err)
		}
		chain = append(chain, cert)
	}
	return chain, nil
}

// nowFunc can be overwritten during tests to return a different time
var nowFunc = time.Now

// Verify verifies a JwtX509Token.
// It checks the signature algorithm
// It verifies if the certificate used to sign the token has a valid chain
// It checks the signature of the jst agains the provided leaf certificate in the x509 header
// It performs additional JWT checks on optional fields like exp, nbf, iat etc.
// Note: it does not verifies the extended key usage! This should be performed by hand.
func (validator JwtX509Validator) Verify(x509Token *JwtX509Token) error {
	var sigAlgAllowed bool
	for _, allowedAlg := range validator.allowedSigningAlgs {
		if allowedAlg == x509Token.sigAlg {
			sigAlgAllowed = true
			break
		}
	}
	if !sigAlgAllowed {
		return fmt.Errorf("signature algorithm %s is not allowed", x509Token.sigAlg)
	}

	leafCert, verifiedChains, err := validator.verifyCertChain(x509Token)
	if err != nil {
		return err
	}

	for _, verifiedChain := range verifiedChains {
		err := validator.checkCertRevocation(verifiedChain)
		if err != nil {
			return err
		}
	}

	// parse the jwt and verify the jwt signature
	token, err := jwt.ParseString(x509Token.raw, jwt.WithVerify(x509Token.sigAlg, leafCert.PublicKey))
	if err != nil {
		return err
	}

	// verify the jwt contents such as expiration
	if err := jwt.Verify(token); err != nil {
		return err
	}

	return nil
}

// verifyCertChain tries to find a valid certificate chain for the given JwtX509Token.
// It uses the provided roots and intermediates.
// If a chain is found, it returns the leaf certificate and the list of valid chains.
func (validator JwtX509Validator) verifyCertChain(x509Token *JwtX509Token) (*x509.Certificate, [][]*x509.Certificate, error) {
	if len(x509Token.chain) == 0 {
		return nil, nil, fmt.Errorf("JWT x5c field does not contain certificates")
	}

	rootsPool := x509.NewCertPool()
	for _, cert := range validator.roots {
		rootsPool.AddCert(cert)
	}
	intermediatesPool := x509.NewCertPool()
	for _, cert := range validator.intermediates {
		intermediatesPool.AddCert(cert)
	}
	verifyOpts := x509.VerifyOptions{
		Intermediates: intermediatesPool,
		Roots:         rootsPool,
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	for _, cert := range x509Token.chain[1:len(x509Token.chain)] {
		verifyOpts.Intermediates.AddCert(cert)
	}

	leafCert := x509Token.chain[0]

	verifiedChains, err := leafCert.Verify(verifyOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to verify certificate chain: %w", err)
	}

	rootCert := verifiedChains[0][len(verifiedChains[0])-1]
	if !bytes.Equal(rootCert.RawIssuer, rootCert.RawSubject) || rootCert.CheckSignatureFrom(rootCert) != nil {
		return nil, nil, fmt.Errorf("certificate '%s' is not a root CA", rootCert.Subject.String())
	}

	return leafCert, verifiedChains, err
}

// checkCertRevocation checks a given certificate chain for revoked certificates.
// The order of the certificates should be that each certificate is issued by the next one. The root comes last.
func (validator JwtX509Validator) checkCertRevocation(verifiedChain []*x509.Certificate) error {
	for i, certToCheck := range verifiedChain {
		issuerIdx := i + 1
		// root is self signed
		if issuerIdx == len(verifiedChain) {
			issuerIdx = i
		}
		issuer := verifiedChain[issuerIdx]

		for _, crlPoint := range certToCheck.CRLDistributionPoints {
			crl, err := validator.crls.GetCrl(crlPoint)
			if err != nil {
				return err
			}
			if crl.HasExpired(nowFunc()) {
				return fmt.Errorf("crl has expired since: %s", crl.TBSCertList.NextUpdate.String())
			}
			if err := issuer.CheckCRLSignature(crl); err != nil {
				return fmt.Errorf("could not check cert agains crl: %w", err)
			}
			revokedCerts := crl.TBSCertList.RevokedCertificates
			for _, revoked := range revokedCerts {
				if certToCheck.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
					return fmt.Errorf("cert with serial '%s' and subject '%s' is revoked", certToCheck.SerialNumber.String(), certToCheck.Subject.String())
				}
			}
		}
	}
	return nil
}
