package api

import (
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-auth/pkg"
	"github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
	"net/http"
)

// Wrapper bridges the generated api types and http logic to the internal types and logic
type Wrapper struct {
	Auth pkg.AuthClient
}

// NutsAuthCreateSession translates http params to internal format, creates a IRMA signing session
// and returns the session pointer to the HTTP stack.
func (api *Wrapper) NutsAuthCreateSession(ctx echo.Context) (err error) {
	// bind params to a generated api format struct
	params := new(ContractSigningRequest)
	if err = ctx.Bind(params); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Could not parse request body")
	}

	// convert generated api format to internal struct
	sessionRequest := pkg.CreateSessionRequest{
		Type:     pkg.ContractType(params.Type),
		Version:  pkg.Version(params.Version),
		Language: pkg.Language(params.Language),
		// FIXME: process the ValidFrom/To from request params
		//ValidFrom: *params.ValidFrom,
		//ValidTo: *params.ValidTo,
	}

	// FIXME: get the acting party from a JWT or config param
	actingParty := "Fixme: fetch acting party from config or http-session"

	// Initiate the actual session
	result, err := api.Auth.CreateContractSession(sessionRequest, actingParty)
	if err != nil {
		if xerrors.Is(err, pkg.ErrContractNotFound) {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
		return
	}

	// convert internal result back to generated api format
	answer := CreateSessionResult{
		QrCodeInfo: IrmaQR{U: string(result.QrCodeInfo.URL), Irmaqr: string(result.QrCodeInfo.Type)},
		SessionId:  result.SessionID,
	}

	return ctx.JSON(http.StatusCreated, answer)
}

// NutsAuthSessionRequestStatus gets the current status or the IRMA signing session,
// it translates the result to the api format and returns it to the HTTP stack
// If the session is not found it returns a 404
func (api *Wrapper) NutsAuthSessionRequestStatus(ctx echo.Context, sessionID string) error {
	sessionStatus, err := api.Auth.ContractSessionStatus(sessionID)
	if err != nil {
		if xerrors.Is(err, pkg.ErrSessionNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, err.Error())
		}
		return err
	}

	// convert internal result back to generated api format
	var disclosedAttributes []DisclosedAttribute
	for _, attr := range sessionStatus.Disclosed {
		value := make(map[string]interface{})
		for key, val := range map[string]string(attr.Value) {
			value[key] = val
		}

		disclosedAttributes = append(disclosedAttributes, DisclosedAttribute{
			Identifier: attr.Identifier.String(),
			Value:      value,
			Rawvalue:   attr.RawValue,
			Status:     string(attr.Status),
		})
	}

	nutsAuthToken := string(sessionStatus.NutsAuthToken)
	proofStatus := string(sessionStatus.ProofStatus)

	answer := SessionResult{
		Disclosed: disclosedAttributes,
		Status:    string(sessionStatus.Status),
		Token:     string(sessionStatus.Token),
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

// NutsAuthValidateContract translates the request params to an internal format, it
// calls the engine's validator and translates the results to the API format and returns
// the answer to the HTTP stack
func (api *Wrapper) NutsAuthValidateContract(ctx echo.Context) error {
	params := &ValidationRequest{}
	if err := ctx.Bind(params); err != nil {
		return err
	}
	logrus.Debug(params)

	validationRequest := pkg.ValidationRequest{
		ContractFormat: pkg.ContractFormat(params.ContractFormat),
		ContractString: params.ContractString,
		ActingPartyCN:  params.ActingPartyCn,
	}

	validationResponse, err := api.Auth.ValidateContract(validationRequest)

	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// convert internal result back to generated api format
	signerAttributes := make(map[string]interface{})
	for k, v := range validationResponse.DisclosedAttributes {
		signerAttributes[k] = v
	}

	answer := ValidationResult{
		ContractFormat:   string(validationResponse.ContractFormat),
		SignerAttributes: signerAttributes,
		ValidationResult: string(validationResponse.ValidationResult),
	}

	return ctx.JSON(http.StatusOK, answer)
}

// NutsAuthGetContractByType calls the engines GetContractByType and translate the answer to
// the API format and returns the the answer back to the HTTP stack
func (api *Wrapper) NutsAuthGetContractByType(ctx echo.Context, contractType string, params NutsAuthGetContractByTypeParams) error {
	// convert generated data types to internal types
	var contractLanguage pkg.Language
	if params.Language != nil {
		contractLanguage = pkg.Language(*params.Language)
	}
	contractVersion := pkg.Version(*params.Version)

	// get contract
	contract, err := api.Auth.ContractByType(pkg.ContractType(contractType), contractLanguage, contractVersion)
	if xerrors.Is(err, pkg.ErrContractNotFound) {
		return echo.NewHTTPError(http.StatusNotFound, err.Error())
	} else if err != nil {
		return err
	}

	// convert internal data types to generated api types
	answer := Contract{
		Language:           Language(contract.Language),
		Template:           &contract.Template,
		TemplateAttributes: contract.TemplateAttributes,
		Type:               Type(contract.Type),
		Version:            Version(contract.Version),
	}

	return ctx.JSON(http.StatusOK, answer)
}
