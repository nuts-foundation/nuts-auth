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

package oauth

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/nuts-foundation/nuts-auth/pkg/contract"
	nutsConsentClient "github.com/nuts-foundation/nuts-consent-store/client"
	nutsConsent "github.com/nuts-foundation/nuts-consent-store/pkg"
	nutsCrypto "github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg/cert"
	nutsCryptoTypes "github.com/nuts-foundation/nuts-crypto/pkg/types"
	core "github.com/nuts-foundation/nuts-go-core"
	nutsRegistry "github.com/nuts-foundation/nuts-registry/pkg"
	errors2 "github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/nuts-foundation/nuts-auth/pkg/services"
)

const oauthKeyQualifier = "oauth"

var errMissingVendorID = errors.New("missing vendorID")
var errIncorrectNumberOfEndpoints = errors.New("none or multiple registered endpoints found")
var errMissingCertificate = errors.New("missing x5c header")
var errInvalidX5cHeader = errors.New("invalid x5c header")
var errInvalidClientCert = errors.New("invalid TLS client certificate")

const errInvalidIssuerFmt = "invalid jwt.issuer: %w"
const errInvalidSubjectFmt = "invalid jwt.subject: %w"

type service struct {
	vendorID          core.PartyID
	crypto            nutsCrypto.Client
	registry          nutsRegistry.RegistryClient
	consent           nutsConsent.ConsentStoreClient
	oauthKeyEntity    nutsCryptoTypes.KeyIdentifier
	contractValidator services.ContractValidator
}

type validationContext struct {
	rawJwtBearerToken        string
	jwtBearerToken           *services.NutsJwtBearerToken
	actorName                string
	vendor                   core.PartyID
	contractValidationResult *services.ContractValidationResult
}

func NewOAuthService(vendorID core.PartyID, cryptoClient nutsCrypto.Client, registryClient nutsRegistry.RegistryClient, contractValidator services.ContractValidator) services.OAuthClient {
	return &service{
		vendorID:          vendorID,
		crypto:            cryptoClient,
		registry:          registryClient,
		contractValidator: contractValidator,
	}
}

// OauthBearerTokenMaxValidity is the number of seconds that a bearer token is valid
const OauthBearerTokenMaxValidity = 5

func (s *service) Configure() (err error) {
	if s.vendorID.IsZero() {
		err = errMissingVendorID
		return
	}

	s.oauthKeyEntity = nutsCryptoTypes.KeyForEntity(nutsCryptoTypes.LegalEntity{URI: s.vendorID.String()}).WithQualifier(oauthKeyQualifier)

	if !s.crypto.PrivateKeyExists(s.oauthKeyEntity) {
		logrus.Info("Missing OAuth JWT signing key, generating new one")
		s.crypto.GenerateKeyPair(s.oauthKeyEntity, false)
	}

	s.consent = nutsConsentClient.NewConsentStoreClient()

	return
}

// CreateAccessToken extracts the claims out of the request, checks the validity and builds the access token
func (s *service) CreateAccessToken(request services.CreateAccessTokenRequest) (*services.AccessTokenResult, error) {
	context := validationContext{
		rawJwtBearerToken: request.RawJwtBearerToken,
	}

	// extract the JwtBearerToken, validates according to RFC003 §5.2.1.1
	// also check if used algorithms are according to spec (ES*** and PS***)
	// and checks basic validity. Set jwtBearerToken in validationContext
	if err := s.parseAndValidateJwtBearerToken(&context); err != nil {
		return nil, fmt.Errorf("jwt bearer token validation failed: %w", err)
	}

	// check the maximum validity, according to RFC003 §5.2.1.4
	if context.jwtBearerToken.ExpiresAt-context.jwtBearerToken.IssuedAt > OauthBearerTokenMaxValidity {
		return nil, errors.New("JWT validity to long")
	}

	// check the actor against the registry, according to RFC003 §5.2.1.3
	// checks signing certificate and sets vendor, actorName in validationContext
	if err := s.validateIssuer(&context); err != nil {
		return nil, err
	}

	// check if client certificate is issued by vendor according to RFC003 §5.2.1.2
	if err := s.validateClientCertificate(&context, request.ClientCert); err != nil {
		return nil, err
	}

	// check if the custodian is registered by this vendor, according to RFC003 §5.2.1.8
	if err := s.validateSubject(&context); err != nil {
		return nil, err
	}

	// Validate the AuthTokenContainer, according to RFC003 §5.2.1.5
	// todo: request.VendorIdentifier is deprecated, remove in 0.17
	var err error
	if context.contractValidationResult, err = s.contractValidator.ValidateJwt(context.jwtBearerToken.AuthTokenContainer, request.VendorIdentifier); err != nil {
		return nil, fmt.Errorf("identity token validation failed: %w", err)
	}
	if context.contractValidationResult.ValidationResult == services.Invalid {
		return nil, fmt.Errorf("identity validation failed")
	}
	// checks if the name from the login contract matches with the registered name of the issuer.
	if err = s.validateActor(&context); err != nil {
		return nil, err
	}

	// validate the endpoint in aud, according to RFC003 §5.2.1.6
	// the aud field must have the identifier of the endpoint registered by the vendor of this node!
	// this is needed to prevent relay attacks.
	// todo: implement when services and endpoints in registry have been implemented (https://github.com/nuts-foundation/nuts-registry/issues/156)

	// validate the legal base, according to RFC003 §5.2.1.7 if sid is present
	if err = s.validateLegalBase(context.jwtBearerToken); err != nil {
		return nil, err
	}

	accessToken, err := s.buildAccessToken(&context)
	if err != nil {
		return nil, err
	}

	return &services.AccessTokenResult{AccessToken: accessToken}, nil
}

// checks if the name from the login contract matches with the registered name of the issuer.
func (s *service) validateActor(context *validationContext) error {
	if context.contractValidationResult.ContractAttributes[contract.LegalEntityAttr] != context.actorName {
		return errors.New("legal entity mismatch")
	}
	return nil
}

// check the actor against the registry, according to RFC003 §5.2.1.3
// we do this by getting the validation chain for the certificate in the x5c header and check the vendorID SAN from the root
// with the vendorId of the actor. It returns the actor name which must match the login contract.
func (s *service) validateIssuer(context *validationContext) error {
	validationTime := time.Unix(context.jwtBearerToken.IssuedAt, 0)
	var vendor core.PartyID

	actorPartyID, err := core.ParsePartyID(context.jwtBearerToken.Issuer)
	if err != nil {
		return fmt.Errorf(errInvalidIssuerFmt, err)
	}
	actor, err := s.registry.OrganizationById(actorPartyID)
	if err != nil {
		return fmt.Errorf(errInvalidIssuerFmt, err)
	}
	chains, err := s.crypto.TrustStore().VerifiedChain(context.jwtBearerToken.SigningCertificate, validationTime)
	if err != nil || len(chains) == 0 {
		return fmt.Errorf(errInvalidIssuerFmt, err)
	}

	match := false
	for _, chain := range chains {
		root := chain[len(chain)-1]
		vendor, err = cert.VendorIDFromCertificate(root)
		if err != nil {
			fmt.Errorf("no vendorID in SAN: %w", err)
		}
		if vendor.String() == actor.Vendor.String() {
			match = true
			break
		}
	}
	if !match {
		return errors.New("certificate from x5c is no sibling of actor signing certificate")
	}

	context.actorName = actor.Name
	context.vendor = vendor

	return nil
}

func (s *service) validateClientCertificate(context *validationContext, pemEncodedCertificate string) error {
	validationTime := time.Unix(context.jwtBearerToken.IssuedAt, 0)
	var vendor core.PartyID

	c, err := cert.PemToX509([]byte(pemEncodedCertificate))
	if err != nil {
		return errInvalidClientCert
	}

	chains, err := s.crypto.TrustStore().VerifiedChain(c, validationTime)
	if err != nil || len(chains) == 0 {
		return errInvalidClientCert
	}

	match := false
	for _, chain := range chains {
		root := chain[len(chain)-1]
		vendor, err = cert.VendorIDFromCertificate(root)
		if err != nil {
			fmt.Errorf("no vendorID in SAN: %w", err)
		}
		if vendor.String() == context.vendor.String() {
			match = true
			break
		}
	}
	if !match {
		return errors.New("certificate from TLS is not issued by same vendor as x5c signing certificate")
	}

	return nil
}

// check if the custodian is registered by this vendor, according to RFC003 §5.2.1.8
func (s *service) validateSubject(context *validationContext) error {
	custPartyID, err := core.ParsePartyID(context.jwtBearerToken.Subject)
	if err != nil {
		return fmt.Errorf(errInvalidSubjectFmt, err)
	}
	custodian, err := s.registry.OrganizationById(custPartyID)
	if err != nil {
		return fmt.Errorf(errInvalidSubjectFmt, err)
	}
	if custodian.Vendor.String() != context.vendor.String() {
		return fmt.Errorf(errInvalidSubjectFmt, errors.New("organisation.vendor doesn't match with vendorID of this node"))
	}

	return nil
}

// validate the legal base, according to RFC003 §5.2.1.7 if sid is present
// use consent store
func (s *service) validateLegalBase(jwtBearerToken *services.NutsJwtBearerToken) error {
	validationTime := time.Unix(jwtBearerToken.IssuedAt, 0)

	if jwtBearerToken.SubjectID != "" {
		legalBase, err := s.consent.QueryConsent(context.Background(), &jwtBearerToken.Issuer, &jwtBearerToken.Subject, &jwtBearerToken.SubjectID, &validationTime)
		if err != nil {
			return fmt.Errorf("legal base validation failed: %w", err)
		}
		if len(legalBase) == 0 {
			return errors.New("subject scope requested but no legal base present")
		}
	}

	return nil
}

// CreateJwtBearerToken creates a JwtBearerToken from the given CreateJwtBearerTokenRequest
func (s *service) CreateJwtBearerToken(request services.CreateJwtBearerTokenRequest) (*services.JwtBearerTokenResult, error) {
	// todo add checks for missing values?
	custodian, err := core.ParsePartyID(request.Custodian)
	if err != nil {
		return nil, err
	}

	endpointType := services.OAuthEndpointType
	epoints, err := s.registry.EndpointsByOrganizationAndType(custodian, &endpointType)
	if err != nil {
		return nil, err
	}
	if len(epoints) != 1 {
		return nil, errIncorrectNumberOfEndpoints
	}

	jwtBearerToken := claimsFromRequest(request, string(epoints[0].Identifier))

	keyVals, err := jwtBearerToken.AsMap()
	if err != nil {
		return nil, err
	}

	signingString, err := s.crypto.SignJWTRFC003(keyVals)
	if err != nil {
		return nil, err
	}

	return &services.JwtBearerTokenResult{BearerToken: signingString}, nil
}

var timeFunc = time.Now

// standalone func for easier testing
func claimsFromRequest(request services.CreateJwtBearerTokenRequest, audience string) services.NutsJwtBearerToken {
	return services.NutsJwtBearerToken{
		StandardClaims: jwt.StandardClaims{
			Audience:  audience,
			ExpiresAt: timeFunc().Add(5 * time.Second).Unix(),
			IssuedAt:  timeFunc().Unix(),
			Issuer:    request.Actor,
			NotBefore: 0,
			Subject:   request.Custodian,
		},
		AuthTokenContainer: request.IdentityToken,
		SubjectID:          request.Subject,
	}
}

// IntrospectAccessToken fills the fields in NutsAccessToken from the given Jwt Access Token
func (s *service) IntrospectAccessToken(token string) (*services.NutsAccessToken, error) {
	acClaims, err := s.parseAndValidateAccessToken(token)
	return acClaims, err
}

// ParseAndValidateJwtBearerToken validates the jwt signature and returns the containing claims
func (s *service) parseAndValidateJwtBearerToken(context *validationContext) error {
	parser := &jwt.Parser{ValidMethods: services.ValidJWTAlg}
	token, err := parser.ParseWithClaims(context.rawJwtBearerToken, &services.NutsJwtBearerToken{}, func(token *jwt.Token) (i interface{}, e error) {
		// get public key from x5c header
		certificate, err := getCertificateFromHeaders(token)
		if err != nil {
			return nil, err
		}

		return certificate.PublicKey, nil
	})

	if token != nil && token.Valid {
		if claims, ok := token.Claims.(*services.NutsJwtBearerToken); ok {
			// this should be ok since it has already succeeded before
			claims.SigningCertificate, _ = getCertificateFromHeaders(token)
			context.jwtBearerToken = claims
			return nil
		}
	}

	return err
}

func getCertificateFromHeaders(token *jwt.Token) (*x509.Certificate, error) {
	h, ok := token.Header["x5c"]
	if !ok {
		return nil, errMissingCertificate
	}
	i, ok := h.([]interface{})
	if !ok {
		return nil, errInvalidX5cHeader
	}
	if len(i) != 1 {
		return nil, errInvalidX5cHeader
	}
	c, ok := i[0].(string)
	if !ok {
		return nil, errInvalidX5cHeader
	}
	bytes, err := base64.StdEncoding.DecodeString(c)
	if err != nil {
		return nil, errors2.Wrap(err, errInvalidX5cHeader.Error())
	}
	return x509.ParseCertificate(bytes)
}

// ParseAndValidateAccessToken parses and validates an accesstoken string and returns a filled in NutsAccessToken.
func (s *service) parseAndValidateAccessToken(accessToken string) (*services.NutsAccessToken, error) {
	parser := &jwt.Parser{ValidMethods: services.ValidJWTAlg}
	token, err := parser.ParseWithClaims(accessToken, &services.NutsAccessToken{}, func(token *jwt.Token) (i interface{}, e error) {
		// Check if the care provider which signed the token is managed by this node
		if !s.crypto.PrivateKeyExists(s.oauthKeyEntity) {
			return nil, errors.New("invalid signature")
		}

		var sk crypto.Signer
		if sk, e = s.crypto.GetPrivateKey(s.oauthKeyEntity); e != nil {
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

// todo split this func for easier testing
// BuildAccessToken builds an access token based on the oauth claims and the identity of the user provided by the identityValidationResult
// The token gets signed with the custodians private key and returned as a string.
func (s *service) buildAccessToken(context *validationContext) (string, error) {
	identityValidationResult := context.contractValidationResult
	jwtBearerToken := context.jwtBearerToken

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
	token, err := s.crypto.SignJWT(keyVals, s.oauthKeyEntity)
	if err != nil {
		return token, fmt.Errorf("could not build accessToken: %w", err)
	}

	return token, err
}
