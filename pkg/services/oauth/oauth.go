package oauth

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	nutsCrypto "github.com/nuts-foundation/nuts-crypto/pkg"
	nutsCryptoTypes "github.com/nuts-foundation/nuts-crypto/pkg/types"
	core "github.com/nuts-foundation/nuts-go-core"
	nutsRegistry "github.com/nuts-foundation/nuts-registry/pkg"
	"github.com/sirupsen/logrus"

	"github.com/nuts-foundation/nuts-auth/pkg/services"
)

var _ services.AccessTokenHandler = (*OAuthService)(nil)

const oauthKeyQualifier = "ouath"

var ErrMissingVendorID = errors.New("missing VendorID")

type OAuthService struct {
	VendorID       core.PartyID
	Crypto         nutsCrypto.Client
	Registry       nutsRegistry.RegistryClient
	oauthKeyEntity nutsCryptoTypes.KeyIdentifier
}

func (s *OAuthService) Configure() (err error) {
	if s.VendorID.IsZero() {
		err = ErrMissingVendorID
		return
	}

	s.oauthKeyEntity = nutsCryptoTypes.KeyForEntity(nutsCryptoTypes.LegalEntity{URI: s.VendorID.String()}).WithQualifier(oauthKeyQualifier)

	if !s.Crypto.PrivateKeyExists(s.oauthKeyEntity) {
		logrus.Info("Missing OAuth JWT signing key, generating new one")
		s.Crypto.GenerateKeyPair(s.oauthKeyEntity, false)
	}
	return
}

// CreateJwtBearerToken creates a JwtBearerTokenResult containing a jwtBearerToken from a CreateJwtBearerTokenRequest.
func (s *OAuthService) CreateJwtBearerToken(request *services.CreateJwtBearerTokenRequest) (*services.JwtBearerTokenResult, error) {
	jti, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	jwtBearerToken := services.NutsJwtBearerToken{
		StandardClaims: jwt.StandardClaims{
			//Audience:  endpoint.Identifier.String(),
			ExpiresAt: time.Now().Add(30 * time.Minute).Unix(),
			Id:        jti.String(),
			IssuedAt:  time.Now().Unix(),
			Issuer:    request.Actor,
			NotBefore: 0,
			Subject:   request.Custodian,
		},
		IdentityToken: request.IdentityToken,
		SubjectID:     request.Subject,
		Scope:         request.Scope,
	}

	var keyVals map[string]interface{}
	inrec, _ := json.Marshal(jwtBearerToken)
	if err := json.Unmarshal(inrec, &keyVals); err != nil {
		return nil, err
	}

	signingString, err := s.Crypto.SignJWT(keyVals, nutsCryptoTypes.KeyForEntity(nutsCryptoTypes.LegalEntity{URI: request.Actor}))
	if err != nil {
		return nil, err
	}

	return &services.JwtBearerTokenResult{BearerToken: signingString}, nil
}

// ParseAndValidateJwtBearerToken validates the jwt signature and returns the containing claims
func (s *OAuthService) ParseAndValidateJwtBearerToken(acString string) (*services.NutsJwtBearerToken, error) {
	parser := &jwt.Parser{ValidMethods: []string{jwt.SigningMethodRS256.Name}}
	token, err := parser.ParseWithClaims(acString, &services.NutsJwtBearerToken{}, func(token *jwt.Token) (i interface{}, e error) {
		legalEntity, err := parseTokenIssuer(token.Claims.(*services.NutsJwtBearerToken).Issuer)
		if err != nil {
			return nil, err
		}

		// get public key
		org, err := s.Registry.OrganizationById(legalEntity)
		if err != nil {
			return nil, err
		}

		pk, err := org.CurrentPublicKey()
		if err != nil {
			return nil, err
		}

		return pk.Materialize()
	})

	if token != nil && token.Valid {
		if claims, ok := token.Claims.(*services.NutsJwtBearerToken); ok {
			return claims, nil
		}
	}

	return nil, err
}

// ParseAndValidateAccessToken parses and validates an accesstoken string and returns a filled in NutsAccessToken.
func (s *OAuthService) ParseAndValidateAccessToken(accessToken string) (*services.NutsAccessToken, error) {
	parser := &jwt.Parser{ValidMethods: []string{jwt.SigningMethodRS256.Name}}
	token, err := parser.ParseWithClaims(accessToken, &services.NutsAccessToken{}, func(token *jwt.Token) (i interface{}, e error) {
		// Check if the care provider which signed the token is managed by this node
		if !s.Crypto.PrivateKeyExists(s.oauthKeyEntity) {
			return nil, fmt.Errorf("invalid token: not signed by this node")
		}

		var sk crypto.Signer
		if sk, e = s.Crypto.GetPrivateKey(s.oauthKeyEntity); e != nil {
			return
		}

		// get public key
		i = sk.Public()
		return
	})

	if token != nil && token.Valid {
		if claims, ok := token.Claims.(*services.NutsAccessToken); ok {
			return claims, nil
		}
	}
	return nil, err
}

// BuildAccessToken builds an access token based on the oauth claims and the identity of the user provided by the identityValidationResult
// The token gets signed with the custodians private key and returned as a string.
func (s *OAuthService) BuildAccessToken(jwtBearerToken *services.NutsJwtBearerToken, identityValidationResult *services.ContractValidationResult) (string, error) {

	if identityValidationResult.ValidationResult != services.Valid {
		return "", fmt.Errorf("could not build accessToken: %w", errors.New("invalid contract"))
	}

	issuer := jwtBearerToken.Subject
	if issuer == "" {
		return "", fmt.Errorf("could not build accessToken: %w", errors.New("subject is missing"))
	}

	at := services.NutsAccessToken{
		StandardClaims: jwt.StandardClaims{
			// Expires in 15 minutes
			ExpiresAt: time.Now().Add(time.Minute * 15).Unix(),
			IssuedAt:  time.Now().Unix(),
			Issuer:    issuer,
			Subject:   jwtBearerToken.Issuer,
		},
		SubjectID: jwtBearerToken.SubjectID,
		Scope:     jwtBearerToken.Scope,
		// based on
		// https://privacybydesign.foundation/attribute-index/en/pbdf.gemeente.personalData.html
		// https://privacybydesign.foundation/attribute-index/en/pbdf.pbdf.email.html
		// and
		// https://openid.net/specs/openid-connect-basic-1_0.html#StandardClaims
		FamilyName: identityValidationResult.DisclosedAttributes["gemeente.personalData.familyname"],
		GivenName:  identityValidationResult.DisclosedAttributes["gemeente.personalData.firstnames"],
		Prefix:     identityValidationResult.DisclosedAttributes["gemeente.personalData.prefix"],
		Name:       identityValidationResult.DisclosedAttributes["gemeente.personalData.fullname"],
		Email:      identityValidationResult.DisclosedAttributes["pbdf.email.email"],
	}

	var keyVals map[string]interface{}
	inrec, _ := json.Marshal(at)
	if err := json.Unmarshal(inrec, &keyVals); err != nil {
		return "", err
	}

	// Sign with the private key of the issuer
	token, err := s.Crypto.SignJWT(keyVals, s.oauthKeyEntity)
	if err != nil {
		return token, fmt.Errorf("could not build accessToken: %w", err)
	}

	return token, err
}

func parseTokenIssuer(issuer string) (core.PartyID, error) {
	if issuer == "" {
		return core.PartyID{}, ErrLegalEntityNotProvided
	}
	if result, err := core.ParsePartyID(issuer); err != nil {
		return core.PartyID{}, fmt.Errorf("invalid token issuer: %w", err)
	} else {
		return result, nil
	}
}

var ErrLegalEntityNotProvided = errors.New("legalEntity not provided")
