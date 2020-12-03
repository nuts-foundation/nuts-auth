// Package v0 provides primitives to interact the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen DO NOT EDIT.
package v0

import (
	"fmt"
	"net/http"

	"github.com/deepmap/oapi-codegen/pkg/runtime"
	"github.com/labstack/echo/v4"
)

// AccessTokenRequestFailedResponse defines model for AccessTokenRequestFailedResponse.
type AccessTokenRequestFailedResponse struct {
	Error string `json:"error"`

	// Human-readable ASCII text providing additional information, used to assist the client developer in understanding the error that occurred.
	ErrorDescription string `json:"error_description"`
}

// AccessTokenResponse defines model for AccessTokenResponse.
type AccessTokenResponse struct {

	// The access token issued by the authorization server.
	// Could be a signed JWT or a random number. It should not have a meaning to the client.
	AccessToken string `json:"access_token"`

	// The lifetime in seconds of the access token.
	ExpiresIn float32 `json:"expires_in"`

	// The type of the token issued
	TokenType string `json:"token_type"`
}

// Contract defines model for Contract.
type Contract struct {

	// Language of the contract in all caps
	Language           Language  `json:"language"`
	SignerAttributes   *[]string `json:"signer_attributes,omitempty"`
	Template           *string   `json:"template,omitempty"`
	TemplateAttributes *[]string `json:"template_attributes,omitempty"`

	// Type of which contract to sign
	Type Type `json:"type"`

	// Version of the contract
	Version Version `json:"version"`
}

// ContractSigningRequest defines model for ContractSigningRequest.
type ContractSigningRequest struct {

	// Language of the contract in all caps
	Language Language `json:"language"`

	// Identifier of the legalEntity as registered in the Nuts registry
	LegalEntity LegalEntity `json:"legalEntity"`

	// Type of which contract to sign
	Type Type `json:"type"`

	// ValidFrom describes the time from which this contract should be considered valid
	ValidFrom *string `json:"valid_from,omitempty"`

	// ValidTo describes the time until this contract should be considered valid
	ValidTo *string `json:"valid_to,omitempty"`

	// Version of the contract
	Version Version `json:"version"`
}

// CreateAccessTokenRequest defines model for CreateAccessTokenRequest.
type CreateAccessTokenRequest struct {

	// Base64 encoded JWT following rfc7523 and the Nuts documentation
	Assertion string `json:"assertion"`

	// always must contain the value "urn:ietf:params:oauth:grant-type:jwt-bearer"
	GrantType string `json:"grant_type"`
}

// CreateJwtBearerTokenRequest defines model for CreateJwtBearerTokenRequest.
type CreateJwtBearerTokenRequest struct {
	Actor     string `json:"actor"`
	Custodian string `json:"custodian"`

	// Base64 encoded IRMA contract conaining the identity of the performer
	Identity string `json:"identity"`

	// Space-delimited list of strings. For what kind of operations can the access token be used? Scopes will be specified for each use-case
	Scope   string  `json:"scope"`
	Subject *string `json:"subject,omitempty"`
}

// CreateSessionResult defines model for CreateSessionResult.
type CreateSessionResult struct {

	// Qr contains the data of an IRMA session QR (as generated by irma_js), suitable for NewSession()
	QrCodeInfo IrmaQR `json:"qr_code_info"`

	// a session identifier
	SessionId string `json:"session_id"`
}

// DisclosedAttribute defines model for DisclosedAttribute.
type DisclosedAttribute struct {
	Identifier string                 `json:"identifier"`
	Rawvalue   *string                `json:"rawvalue,omitempty"`
	Status     string                 `json:"status"`
	Value      map[string]interface{} `json:"value"`
}

// DisclosedAttributeIndex defines model for DisclosedAttributeIndex.
type DisclosedAttributeIndex struct {
	Attr *int `json:"attr,omitempty"`
	Cred *int `json:"cred,omitempty"`
}

// ErrorString defines model for ErrorString.
type ErrorString string

// IrmaQR defines model for IrmaQR.
type IrmaQR struct {
	Irmaqr string `json:"irmaqr"`

	// Server with which to perform the session (URL)
	U string `json:"u"`
}

// JwtBearerTokenResponse defines model for JwtBearerTokenResponse.
type JwtBearerTokenResponse struct {
	BearerToken string `json:"bearer_token"`
}

// Language defines model for Language.
type Language string

// LegalEntity defines model for LegalEntity.
type LegalEntity string

// Proof defines model for Proof.
type Proof interface{}

// ProofD defines model for ProofD.
type ProofD struct {
	A          *float32                `json:"A,omitempty"`
	ADisclosed *map[string]interface{} `json:"a_disclosed,omitempty"`
	AResponses *map[string]interface{} `json:"a_responses,omitempty"`
	C          *float32                `json:"c,omitempty"`
	EResponse  *float32                `json:"e_response,omitempty"`
	VResponse  *float32                `json:"v_response,omitempty"`
}

// ProofP defines model for ProofP.
type ProofP struct {
	P         *float32 `json:"P,omitempty"`
	C         *float32 `json:"c,omitempty"`
	SResponse *float32 `json:"s_response,omitempty"`
}

// ProofS defines model for ProofS.
type ProofS struct {
	C         *float32 `json:"c,omitempty"`
	EResponse *float32 `json:"e_response,omitempty"`
}

// ProofU defines model for ProofU.
type ProofU struct {
	U              *float32 `json:"U,omitempty"`
	C              *float32 `json:"c,omitempty"`
	SResponse      *float32 `json:"s_response,omitempty"`
	VPrimeResponse *float32 `json:"v_prime_response,omitempty"`
}

// RemoteError defines model for RemoteError.
type RemoteError struct {
	Description *string `json:"description,omitempty"`
	Error       *string `json:"error,omitempty"`
	Message     *string `json:"message,omitempty"`
	Stacktrace  *string `json:"stacktrace,omitempty"`
	Status      *int    `json:"status,omitempty"`
}

// SessionResult defines model for SessionResult.
type SessionResult struct {
	Disclosed *[]DisclosedAttribute `json:"disclosed,omitempty"`
	Error     *RemoteError          `json:"error,omitempty"`

	// Base64 encoded JWT that can be used as Bearer Token
	NutsAuthToken *string        `json:"nuts_auth_token,omitempty"`
	ProofStatus   *string        `json:"proofStatus,omitempty"`
	Signature     *SignedMessage `json:"signature,omitempty"`
	Status        string         `json:"status"`

	// the token originally given in the request
	Token string `json:"token"`
	Type  string `json:"type"`
}

// SignedMessage defines model for SignedMessage.
type SignedMessage struct {
	Context   *float32                     `json:"context,omitempty"`
	Indices   *[][]DisclosedAttributeIndex `json:"indices,omitempty"`
	Message   *string                      `json:"message,omitempty"`
	Nonce     *float32                     `json:"nonce,omitempty"`
	Signature *[]Proof                     `json:"signature,omitempty"`
	Timestamp *Timestamp                   `json:"timestamp,omitempty"`
}

// Timestamp defines model for Timestamp.
type Timestamp struct {
	Time *int64 `json:"time,omitempty"`
}

// TokenIntrospectionRequest defines model for TokenIntrospectionRequest.
type TokenIntrospectionRequest struct {
	Token string `json:"token"`
}

// TokenIntrospectionResponse defines model for TokenIntrospectionResponse.
type TokenIntrospectionResponse struct {

	// True if the token is active, false if the token is expired, malformed etc.
	Active bool `json:"active"`

	// As per rfc7523 https://tools.ietf.org/html/rfc7523>, the aud must be the
	// token endpoint. This can be taken from the Nuts registry.
	Aud *string `json:"aud,omitempty"`

	// End-User's preferred e-mail address. Should be a personal email and can be used to uniquely identify a user. Just like the email used for an account.
	Email *string `json:"email,omitempty"`
	Exp   *int    `json:"exp,omitempty"`

	// Surname(s) or last name(s) of the End-User.
	FamilyName *string `json:"family_name,omitempty"`

	// Given name(s) or first name(s) of the End-User.
	GivenName *string `json:"given_name,omitempty"`
	Iat       *int    `json:"iat,omitempty"`

	// The subject (not a Nuts subject) contains the URN of the custodian.
	Iss *string `json:"iss,omitempty"`

	// End-User's full name in displayable form including all name parts, possibly including titles and suffixes, ordered according to the End-User's locale and preferences.
	Name *string `json:"name,omitempty"`

	// encoded ops signature. (TBD)
	Osi *string `json:"osi,omitempty"`

	// Surname prefix
	Prefix *string `json:"prefix,omitempty"`
	Scope  *string `json:"scope,omitempty"`

	// The Nuts subject id, patient identifier in the form of an oid encoded BSN.
	Sid *string `json:"sid,omitempty"`

	// The subject is always the acting party, thus the care organization requesting access to data.
	Sub *string `json:"sub,omitempty"`

	// Jwt encoded user identity.
	Usi *string `json:"usi,omitempty"`
}

// Type defines model for Type.
type Type string

// ValidationRequest defines model for ValidationRequest.
type ValidationRequest struct {

	// ActingPartyCN is the common name of the Acting party extracted from the client cert
	ActingPartyCn string `json:"acting_party_cn"`

	// ContractFormat specifies the type of format used for the contract
	ContractFormat string `json:"contract_format"`

	// Base64 encoded contracts, either Irma signature or a JWT
	ContractString string `json:"contract_string"`
}

// ValidationResult defines model for ValidationResult.
type ValidationResult struct {
	ContractFormat   string                 `json:"contract_format"`
	SignerAttributes map[string]interface{} `json:"signer_attributes"`
	ValidationResult string                 `json:"validation_result"`
}

// Version defines model for Version.
type Version string

// CreateAccessTokenJSONBody defines parameters for CreateAccessToken.
type CreateAccessTokenJSONBody CreateAccessTokenRequest

// CreateAccessTokenParams defines parameters for CreateAccessToken.
type CreateAccessTokenParams struct {
	XSslClientCert   string  `json:"X-Ssl-Client-Cert"`
	XNutsLegalEntity *string `json:"X-Nuts-LegalEntity,omitempty"`
}

// VerifyAccessTokenParams defines parameters for VerifyAccessToken.
type VerifyAccessTokenParams struct {
	Authorization string `json:"Authorization"`
}

// CreateSessionJSONBody defines parameters for CreateSession.
type CreateSessionJSONBody ContractSigningRequest

// ValidateContractJSONBody defines parameters for ValidateContract.
type ValidateContractJSONBody ValidationRequest

// GetContractByTypeParams defines parameters for GetContractByType.
type GetContractByTypeParams struct {

	// The version of this contract. If omitted, the most recent version will be returned
	Version  *string `json:"version,omitempty"`
	Language *string `json:"language,omitempty"`
}

// CreateJwtBearerTokenJSONBody defines parameters for CreateJwtBearerToken.
type CreateJwtBearerTokenJSONBody CreateJwtBearerTokenRequest

// CreateAccessTokenRequestBody defines body for CreateAccessToken for application/json ContentType.
type CreateAccessTokenJSONRequestBody CreateAccessTokenJSONBody

// CreateSessionRequestBody defines body for CreateSession for application/json ContentType.
type CreateSessionJSONRequestBody CreateSessionJSONBody

// ValidateContractRequestBody defines body for ValidateContract for application/json ContentType.
type ValidateContractJSONRequestBody ValidateContractJSONBody

// CreateJwtBearerTokenRequestBody defines body for CreateJwtBearerToken for application/json ContentType.
type CreateJwtBearerTokenJSONRequestBody CreateJwtBearerTokenJSONBody

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// Create an access token based on the OAuth JWT Bearer flow.
	// This endpoint must be available to the outside world for other applications to request access tokens.
	// It requires a two-way TLS connection. The client certificate must be a sibling of the signing certificate of the given JWT.
	// The client certificate must be passed using a X-Ssl-Client-Cert header, PEM encoded and urlescaped.
	// (POST /auth/accesstoken)
	CreateAccessToken(ctx echo.Context, params CreateAccessTokenParams) error
	// Verifies the access token given in the Authorization header (as bearer token). If it's a valid access token issued by this server, it'll return a 200 status code.
	// If it cannot be verified it'll return 403. Note that it'll not return the contents of the access token. The introspection API is for that.
	// (HEAD /auth/accesstoken/verify)
	VerifyAccessToken(ctx echo.Context, params VerifyAccessTokenParams) error
	// CreateSessionHandler Initiates an IRMA signing session with the correct contract.
	// (POST /auth/contract/session)
	CreateSession(ctx echo.Context) error
	// returns the result of the contract request
	// (GET /auth/contract/session/{id})
	SessionRequestStatus(ctx echo.Context, id string) error
	// Validate a Nuts Security Contract
	// (POST /auth/contract/validate)
	ValidateContract(ctx echo.Context) error
	// Get a contract by type and version
	// (GET /auth/contract/{contractType})
	GetContractByType(ctx echo.Context, contractType string, params GetContractByTypeParams) error
	// Create a JWT Bearer Token which can be used in the createAccessToken request in the assertion field
	// (POST /auth/jwtbearertoken)
	CreateJwtBearerToken(ctx echo.Context) error
	// Introspection endpoint to retrieve information from an Access Token as described by RFC7662
	// (POST /auth/token_introspection)
	IntrospectAccessToken(ctx echo.Context) error
}

// ServerInterfaceWrapper converts echo contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler ServerInterface
}

// CreateAccessToken converts echo context to params.
func (w *ServerInterfaceWrapper) CreateAccessToken(ctx echo.Context) error {
	var err error

	// Parameter object where we will unmarshal all parameters from the context
	var params CreateAccessTokenParams

	headers := ctx.Request().Header
	// ------------- Required header parameter "X-Ssl-Client-Cert" -------------
	if valueList, found := headers[http.CanonicalHeaderKey("X-Ssl-Client-Cert")]; found {
		var XSslClientCert string
		n := len(valueList)
		if n != 1 {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Expected one value for X-Ssl-Client-Cert, got %d", n))
		}

		err = runtime.BindStyledParameter("simple", false, "X-Ssl-Client-Cert", valueList[0], &XSslClientCert)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter X-Ssl-Client-Cert: %s", err))
		}

		params.XSslClientCert = XSslClientCert
	} else {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Header parameter X-Ssl-Client-Cert is required, but not found"))
	}
	// ------------- Optional header parameter "X-Nuts-LegalEntity" -------------
	if valueList, found := headers[http.CanonicalHeaderKey("X-Nuts-LegalEntity")]; found {
		var XNutsLegalEntity string
		n := len(valueList)
		if n != 1 {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Expected one value for X-Nuts-LegalEntity, got %d", n))
		}

		err = runtime.BindStyledParameter("simple", false, "X-Nuts-LegalEntity", valueList[0], &XNutsLegalEntity)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter X-Nuts-LegalEntity: %s", err))
		}

		params.XNutsLegalEntity = &XNutsLegalEntity
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.CreateAccessToken(ctx, params)
	return err
}

// VerifyAccessToken converts echo context to params.
func (w *ServerInterfaceWrapper) VerifyAccessToken(ctx echo.Context) error {
	var err error

	// Parameter object where we will unmarshal all parameters from the context
	var params VerifyAccessTokenParams

	headers := ctx.Request().Header
	// ------------- Required header parameter "Authorization" -------------
	if valueList, found := headers[http.CanonicalHeaderKey("Authorization")]; found {
		var Authorization string
		n := len(valueList)
		if n != 1 {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Expected one value for Authorization, got %d", n))
		}

		err = runtime.BindStyledParameter("simple", false, "Authorization", valueList[0], &Authorization)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter Authorization: %s", err))
		}

		params.Authorization = Authorization
	} else {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Header parameter Authorization is required, but not found"))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.VerifyAccessToken(ctx, params)
	return err
}

// CreateSession converts echo context to params.
func (w *ServerInterfaceWrapper) CreateSession(ctx echo.Context) error {
	var err error

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.CreateSession(ctx)
	return err
}

// SessionRequestStatus converts echo context to params.
func (w *ServerInterfaceWrapper) SessionRequestStatus(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "id" -------------
	var id string

	err = runtime.BindStyledParameter("simple", false, "id", ctx.Param("id"), &id)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter id: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.SessionRequestStatus(ctx, id)
	return err
}

// ValidateContract converts echo context to params.
func (w *ServerInterfaceWrapper) ValidateContract(ctx echo.Context) error {
	var err error

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.ValidateContract(ctx)
	return err
}

// GetContractByType converts echo context to params.
func (w *ServerInterfaceWrapper) GetContractByType(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "contractType" -------------
	var contractType string

	err = runtime.BindStyledParameter("simple", false, "contractType", ctx.Param("contractType"), &contractType)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter contractType: %s", err))
	}

	// Parameter object where we will unmarshal all parameters from the context
	var params GetContractByTypeParams
	// ------------- Optional query parameter "version" -------------

	err = runtime.BindQueryParameter("form", true, false, "version", ctx.QueryParams(), &params.Version)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter version: %s", err))
	}

	// ------------- Optional query parameter "language" -------------

	err = runtime.BindQueryParameter("form", true, false, "language", ctx.QueryParams(), &params.Language)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter language: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.GetContractByType(ctx, contractType, params)
	return err
}

// CreateJwtBearerToken converts echo context to params.
func (w *ServerInterfaceWrapper) CreateJwtBearerToken(ctx echo.Context) error {
	var err error

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.CreateJwtBearerToken(ctx)
	return err
}

// IntrospectAccessToken converts echo context to params.
func (w *ServerInterfaceWrapper) IntrospectAccessToken(ctx echo.Context) error {
	var err error

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.IntrospectAccessToken(ctx)
	return err
}

// RegisterHandlers adds each server route to the EchoRouter.
func RegisterHandlers(router interface {
	CONNECT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	DELETE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	GET(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	HEAD(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	OPTIONS(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	PATCH(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	POST(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	PUT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	TRACE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
}, si ServerInterface) {

	wrapper := ServerInterfaceWrapper{
		Handler: si,
	}

	router.POST("/auth/accesstoken", wrapper.CreateAccessToken)
	router.HEAD("/auth/accesstoken/verify", wrapper.VerifyAccessToken)
	router.POST("/auth/contract/session", wrapper.CreateSession)
	router.GET("/auth/contract/session/:id", wrapper.SessionRequestStatus)
	router.POST("/auth/contract/validate", wrapper.ValidateContract)
	router.GET("/auth/contract/:contractType", wrapper.GetContractByType)
	router.POST("/auth/jwtbearertoken", wrapper.CreateJwtBearerToken)
	router.POST("/auth/token_introspection", wrapper.IntrospectAccessToken)

}
