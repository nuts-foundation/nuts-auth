package api

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"

	core "github.com/nuts-foundation/nuts-go-core"

	"github.com/nuts-foundation/nuts-auth/pkg"
	"github.com/nuts-foundation/nuts-auth/pkg/contract"
	"github.com/nuts-foundation/nuts-auth/pkg/services"
)

// Wrapper bridges the generated api types and http logic to the internal types and logic.
// It checks required parameters and message body. It converts data from api to internal types.
// Then passes the internal formats to the AuthClient. Converts internal results back to the generated
// Api types. Handles errors and returns the correct http response. It does not perform any business logic.
type Wrapper struct {
	Auth pkg.AuthClient
}

// TODO: Use the client certificate here, added by a revere proxy. Than the vendor urn can be fetched from the subject alternative name.
var vendorIdentifierFromHeader = func(ctx echo.Context) string {
	return ctx.Request().Header.Get("X-Nuts-LegalEntity")
}

// CreateSession translates http params to internal format, creates a IRMA signing session
// and returns the session pointer to the HTTP stack.
func (api *Wrapper) CreateSession(ctx echo.Context) error {
	// bind params to a generated api format struct
	params := new(ContractSigningRequest)
	if err := ctx.Bind(params); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Could not parse request body: %s", err))
	}

	var vf, vt time.Time
	if params.ValidFrom != nil {
		vft, err := time.Parse("2006-01-02T15:04:05-07:00", *params.ValidFrom)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Could not parse validFrom: %v", err))
		}
		vf = vft
	}
	if params.ValidTo != nil {
		vft, err := time.Parse("2006-01-02T15:04:05-07:00", *params.ValidTo)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Could not parse validTo: %v", err))
		}
		vt = vft
	}

	orgID, err := core.ParsePartyID(string(params.LegalEntity))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid value for param legalEntity: '%s', make sure its in the form 'urn:oid:1.2.3.4:foo'", params.LegalEntity))
	}
	// find legal entity in crypto
	if !api.Auth.KeyExistsFor(orgID) {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Unknown legalEntity, this Nuts node does not seem to be managing '%s'", orgID))
	}

	// translate legal entity to its name
	orgName, err := api.Auth.OrganizationNameByID(orgID)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("No organization registered for legalEntity: %v", err))
	}

	// convert generated api format to internal struct
	sessionRequest := services.CreateSessionRequest{
		Type:        contract.Type(params.Type),
		Version:     contract.Version(params.Version),
		Language:    contract.Language(params.Language),
		LegalEntity: orgName,
		ValidFrom:   vf,
		ValidTo:     vt,
	}

	// Initiate the actual session
	result, err := api.Auth.CreateContractSession(sessionRequest)
	if err != nil {
		if errors.Is(err, contract.ErrContractNotFound) {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
		logrus.WithError(err).Error("error while creating contract session")
		return err
	}

	// convert internal result back to generated api format
	answer := CreateSessionResult{
		QrCodeInfo: IrmaQR{U: string(result.QrCodeInfo.URL), Irmaqr: string(result.QrCodeInfo.Type)},
		SessionId:  result.SessionID,
	}

	return ctx.JSON(http.StatusCreated, answer)
}

// SessionRequestStatus gets the current status or the IRMA signing session,
// it translates the result to the api format and returns it to the HTTP stack
// If the session is not found it returns a 404
func (api *Wrapper) SessionRequestStatus(ctx echo.Context, sessionID string) error {
	sessionStatus, err := api.Auth.ContractSessionStatus(sessionID)
	if err != nil {
		if errors.Is(err, services.ErrSessionNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, err.Error())
		}
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// convert internal result back to generated api format
	var disclosedAttributes []DisclosedAttribute
	if len(sessionStatus.Disclosed) > 0 {
		for _, attr := range sessionStatus.Disclosed[0] {
			value := make(map[string]string)
			for key, val := range map[string]string(attr.Value) {
				value[key] = val
			}

			disclosedAttributes = append(disclosedAttributes, DisclosedAttribute{
				Identifier: attr.Identifier.String(),
				Value:      DisclosedAttribute_Value{value},
				Rawvalue:   attr.RawValue,
				Status:     string(attr.Status),
			})
		}
	}

	nutsAuthToken := sessionStatus.NutsAuthToken
	proofStatus := string(sessionStatus.ProofStatus)

	answer := SessionResult{
		Disclosed: &disclosedAttributes,
		Status:    string(sessionStatus.Status),
		Token:     sessionStatus.Token,
		Type:      string(sessionStatus.Type),
	}
	if nutsAuthToken != "" {
		answer.NutsAuthToken = &nutsAuthToken
	}

	if proofStatus != "" {
		answer.ProofStatus = &proofStatus
	}

	return ctx.JSON(http.StatusOK, answer)
}

// ValidateContract first translates the request params to an internal format, it then
// calls the engine's validator and translates the results to the API format and returns
// the answer to the HTTP stack
func (api *Wrapper) ValidateContract(ctx echo.Context) error {
	params := &ValidationRequest{}
	if err := ctx.Bind(params); err != nil {
		return err
	}
	logrus.Debug(params)

	validationRequest := services.ValidationRequest{
		ContractFormat: services.ContractFormat(params.ContractFormat),
		ContractString: params.ContractString,
		ActingPartyCN:  params.ActingPartyCn,
	}

	validationResponse, err := api.Auth.ValidateContract(validationRequest)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// convert internal result back to generated api format
	signerAttributes := make(map[string]string)
	for k, v := range validationResponse.DisclosedAttributes {
		signerAttributes[k] = v
	}

	answer := ValidationResult{
		ContractFormat:   string(validationResponse.ContractFormat),
		SignerAttributes: ValidationResult_SignerAttributes{AdditionalProperties: signerAttributes},
		ValidationResult: string(validationResponse.ValidationResult),
	}

	return ctx.JSON(http.StatusOK, answer)
}

// GetContractByType calls the engines GetContractByType and translate the answer to
// the API format and returns the the answer back to the HTTP stack
func (api *Wrapper) GetContractByType(ctx echo.Context, contractType string, params GetContractByTypeParams) error {
	// convert generated data types to internal types
	var (
		contractLanguage contract.Language
		contractVersion  contract.Version
	)
	if params.Language != nil {
		contractLanguage = contract.Language(*params.Language)
	}

	if params.Version != nil {
		contractVersion = contract.Version(*params.Version)
	}

	// get contract
	authContract, err := api.Auth.ContractByType(contract.Type(contractType), contractLanguage, contractVersion)
	if errors.Is(err, contract.ErrContractNotFound) {
		return echo.NewHTTPError(http.StatusNotFound, err.Error())
	} else if err != nil {
		return err
	}

	// convert internal data types to generated api types
	answer := Contract{
		Language:           Language(authContract.Language),
		Template:           &authContract.Template,
		TemplateAttributes: &authContract.TemplateAttributes,
		Type:               Type(authContract.Type),
		Version:            Version(authContract.Version),
	}

	return ctx.JSON(http.StatusOK, answer)
}

// CreateAccessToken handles the api call to create an access token.
// It consumes and checks the JWT and returns a smaller sessionToken
func (api *Wrapper) CreateAccessToken(ctx echo.Context) (err error) {
	// Can't use echo.Bind() here since it requires extra tags on generated code
	request := new(CreateAccessTokenRequest)
	request.Assertion = ctx.FormValue("assertion")
	request.GrantType = ctx.FormValue("grant_type")

	if request.GrantType != pkg.JwtBearerGrantType {
		errDesc := fmt.Sprintf("grant_type must be: '%s'", pkg.JwtBearerGrantType)
		errorResponse := AccessTokenRequestFailedResponse{Error: "unsupported_grant_type", ErrorDescription: errDesc}
		return ctx.JSON(http.StatusBadRequest, errorResponse)
	}

	const jwtPattern = `^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$`
	if matched, err := regexp.Match(jwtPattern, []byte(request.Assertion)); !matched || err != nil {
		errDesc := "Assertion must be a valid encoded jwt"
		errorResponse := AccessTokenRequestFailedResponse{Error: "invalid_grant", ErrorDescription: errDesc}
		return ctx.JSON(http.StatusBadRequest, errorResponse)
	}
	vendorID := vendorIdentifierFromHeader(ctx)
	if vendorID == "" {
		errDesc := "Vendor identifier missing in header"
		errorResponse := AccessTokenRequestFailedResponse{Error: "invalid_grant", ErrorDescription: errDesc}
		return ctx.JSON(http.StatusBadRequest, errorResponse)
	}
	catRequest := services.CreateAccessTokenRequest{RawJwtBearerToken: request.Assertion, VendorIdentifier: vendorID}
	acResponse, err := api.Auth.CreateAccessToken(catRequest)
	if err != nil {
		errDesc := err.Error()
		errorResponse := AccessTokenRequestFailedResponse{Error: "invalid_grant", ErrorDescription: errDesc}
		return ctx.JSON(http.StatusBadRequest, errorResponse)
	}
	response := AccessTokenResponse{AccessToken: acResponse.AccessToken}

	return ctx.JSON(http.StatusOK, response)
}

// CreateJwtBearerToken fills a CreateJwtBearerTokenRequest from the request body and passes it to the auth module.
func (api *Wrapper) CreateJwtBearerToken(ctx echo.Context) error {
	requestBody := &CreateJwtBearerTokenRequest{}
	if err := ctx.Bind(requestBody); err != nil {
		return err
	}

	request := services.CreateJwtBearerTokenRequest{
		Actor:         requestBody.Actor,
		Custodian:     requestBody.Custodian,
		IdentityToken: requestBody.Identity,
		Subject:       requestBody.Subject,
		Scope:         requestBody.Scope,
	}
	response, err := api.Auth.CreateJwtBearerToken(request)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, err.Error())
	}

	return ctx.JSON(http.StatusOK, JwtBearerTokenResponse{BearerToken: response.BearerToken})
}

// IntrospectAccessToken takes the access token from the request form value and passes it to the auth client.
func (api *Wrapper) IntrospectAccessToken(ctx echo.Context) error {
	token := ctx.FormValue("token")

	introspectionResponse := TokenIntrospectionResponse{
		Active: false,
	}

	if len(token) == 0 {
		return ctx.JSON(http.StatusOK, introspectionResponse)
	}

	claims, err := api.Auth.IntrospectAccessToken(token)
	if err != nil {
		logrus.WithError(err).Debug("error while inspecting access token")
		return ctx.JSON(http.StatusOK, introspectionResponse)
	}

	exp := int(claims.ExpiresAt)
	iat := int(claims.IssuedAt)

	introspectionResponse = TokenIntrospectionResponse{
		Active:     true,
		Sub:        &claims.Subject,
		Iss:        &claims.Issuer,
		Aud:        &claims.Audience,
		Exp:        &exp,
		Iat:        &iat,
		Sid:        &claims.SubjectID,
		Scope:      &claims.Scope,
		Name:       &claims.Name,
		GivenName:  &claims.GivenName,
		Prefix:     &claims.Prefix,
		FamilyName: &claims.FamilyName,
		Email:      &claims.Email,
	}

	return ctx.JSON(http.StatusOK, introspectionResponse)
}
