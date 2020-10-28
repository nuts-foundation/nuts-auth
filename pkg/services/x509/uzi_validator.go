package x509

import (
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/jwa"

	"github.com/nuts-foundation/nuts-auth/assets"
	"github.com/nuts-foundation/nuts-auth/pkg/contract"
	"github.com/nuts-foundation/nuts-auth/pkg/services"
)

// Uzi Attributes used to sign the message
// See table 12 on page 62 of the Certification Practice Statement (CPS) UZI-register v10.x
// https://zorgcsp.nl/Media/Default/documenten/2020-05-06_RK1%20CPS%20UZI-register%20V10.0.pdf
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

const UziProduction UziEnv = "production"
const UziAcceptation UziEnv = "acceptation"

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
	return *t.contract
}

func certsFromAssets(paths []string) (certs []*x509.Certificate, err error) {
	for _, path := range paths {
		var (
			rawCert []byte
			cert    *x509.Certificate
		)
		rawCert, err = assets.Asset(path)
		if err != nil {
			return
		}

		cert, err = x509.ParseCertificate(rawCert)
		if err != nil {
			return
		}
		certs = append(certs, cert)
	}
	return
}

func NewUziValidator(env UziEnv, contractTemplates *contract.TemplateStore, crls CrlGetter) (validator *UziValidator, err error) {
	var roots []*x509.Certificate
	var intermediates []*x509.Certificate

	if env == UziProduction {
		roots, err = certsFromAssets([]string{
			"certs/uzi-prod/RootCA-G3.cer",
		})
		if err != nil {
			return
		}

		intermediates, err = certsFromAssets([]string{
			"certs/uzi-prod/20190418_UZI-register_Medewerker_op_naam_CA_G3.cer",
			"certs/uzi-prod/20190418_UZI-register_Zorgverlener_CA_G3.cer",
			"certs/uzi-prod/DomOrganisatiePersoonCA-G3.cer",
			"certs/uzi-prod/UZI-register_Medewerker_op_naam_CA_G3.cer",
			"certs/uzi-prod/UZI-register_Zorgverlener_CA_G3.cer",
		})
		if err != nil {
			return
		}
	} else if env == UziAcceptation {
		roots, err = certsFromAssets([]string{
			"certs/uzi-acc/test_zorg_csp_root_ca_g3.cer",
		})
		if err != nil {
			return
		}

		intermediates, err = certsFromAssets([]string{
			"certs/uzi-acc/test_uzi-register_medewerker_op_naam_ca_g3.cer",
			"certs/uzi-acc/test_zorg_csp_level_2_persoon_ca_g3.cer",
		})
		if err != nil {
			return
		}
	}

	if crls == nil {
		crls = NewCachedHttpCrlService()
	}

	validator = &UziValidator{
		validator:         NewJwtX509Validator(roots, intermediates, []jwa.SignatureAlgorithm{jwa.RS256, jwa.RS512}, crls),
		contractTemplates: contractTemplates,
	}
	return
}

func (u UziValidator) Parse(rawAuthToken string) (services.SignedToken, error) {
	x509Token, err := u.validator.Parse(rawAuthToken)
	if err != nil {
		return nil, err
	}
	tokenField, ok := x509Token.token.Get("message")
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
	x509SignedToken, ok := token.(UziSignedToken)
	if !ok {
		return fmt.Errorf("wrong token type")
	}
	return u.validator.Verify(x509SignedToken.jwtX509Token)
}
