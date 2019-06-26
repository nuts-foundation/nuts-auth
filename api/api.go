package api

import (
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-auth/pkg"
	"github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
	"net/http"
)

// ApiWrapper bridges the generated api types and http logic to the internal types and logic
type ApiWrapper struct {
	Auth *pkg.Auth
}

func (api *ApiWrapper) NutsAuthCreateSession(ctx echo.Context) (err error) {
	// bind params to a generated api format struct
	params := new(ContractSigningRequest)
	if err = ctx.Bind(params); err != nil {
		return
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
		return
	}

	// convert internal result back to generated api format
	answer := CreateSessionResult{
		QrCodeInfo: IrmaQR{U: string(result.QrCodeInfo.URL), Irmaqr: string(result.QrCodeInfo.Type)},
		SessionId:  result.SessionId,
	}

	return ctx.JSON(http.StatusCreated, answer)
}

func (api *ApiWrapper) NutsAuthSessionRequestStatus(ctx echo.Context, id string) error {
	sessionId := id
	sessionStatus, err := api.Auth.ContractSessionStatus(sessionId)
	if err != nil {
		return err
	}

	if sessionStatus == nil {
		return echo.NewHTTPError(http.StatusNotFound, "Session not found")
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
		Disclosed:     disclosedAttributes,
		NutsAuthToken: &nutsAuthToken,
		ProofStatus:   &proofStatus,
		Status:        string(sessionStatus.Status),
		Token:         string(sessionStatus.Token),
		Type:          string(sessionStatus.Type),
	}

	return ctx.JSON(http.StatusOK, answer)
}

func (api *ApiWrapper) NutsAuthValidateContract(ctx echo.Context) error {
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
		ContractFormat: string(validationResponse.ContractFormat),
		SignerAttributes: signerAttributes,
		ValidationResult: string(validationResponse.ValidationResult),
	}

	return ctx.JSON(http.StatusOK, answer)
}

func (api *ApiWrapper) NutsAuthGetContractByType(ctx echo.Context, contractType string, params NutsAuthGetContractByTypeParams) error {
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
