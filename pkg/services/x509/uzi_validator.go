package x509

import (
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/jwa"

	"github.com/nuts-foundation/nuts-auth/pkg/contract"
	"github.com/nuts-foundation/nuts-auth/pkg/services"
)

var UziAttributes = []string{
	"oidCa",
	"version",
	"uziNr",
	"cardType",
	"orgID",
	"rollCode",
	"agbCode",
}

type UziSignedToken struct {
	jwtX509Token *JwtX509Token
	contract     *contract.Contract
}

// UziValidator wraps a jwtX509Validator an can check Uzi signed JWTs.
// It can parse and validate a UziSignedToken which implements the SignedToken interface
type UziValidator struct {
	validator         *JwtX509Validator
	contractTemplates *contract.TemplateStore
}

type UziEnv string

const ProductionTree UziEnv = "production"
const AcceptationTree UziEnv = "acceptation"

func (t UziSignedToken) SignerAttributes() map[string]string {
	otherNameStr, err := t.jwtX509Token.SubjectAltNameOtherName()
	if err != nil {
		return nil
	}

	parts := strings.Split(otherNameStr, "-")

	res := map[string]string{}
	for idx, name := range UziAttributes {
		res[name] = parts[idx]
	}
	return res
}

func (t UziSignedToken) Contract() contract.Contract {
	return t.Contract()
}

func NewUziValidator(env UziEnv, contractTemplates *contract.TemplateStore) *UziValidator {
	// TODO: load certs based on the UziEnv
	roots := []*x509.Certificate{}
	intermediates := []*x509.Certificate{}

	validator := &UziValidator{
		validator:         NewJwtX509Validator(roots, intermediates, []jwa.SignatureAlgorithm{jwa.RS256}),
		contractTemplates: contractTemplates,
	}

	return validator
}

func (u UziValidator) Parse(rawAuthToken string) (services.SignedToken, error) {
	x509Token, err := u.validator.Parse(rawAuthToken)
	if err != nil {
		return nil, err
	}
	tokenField, ok := x509Token.token.Get("token")
	if !ok {
		return nil, fmt.Errorf("jwt did not contain token field")
	}
	contractText, ok := tokenField.(string)
	if !ok {
		return nil, fmt.Errorf("token field should contain a string")
	}

	c, err := contract.ParseContractString(contractText, *u.contractTemplates)

	return UziSignedToken{jwtX509Token: x509Token, contract: c}, nil
}

func (u UziValidator) Verify(token services.SignedToken) error {
	return u.Verify(token)
}
