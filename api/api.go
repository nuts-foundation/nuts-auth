package api

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-auth/pkg"
	"github.com/sirupsen/logrus"
)

// Wrapper bridges the generated api types and http logic to the internal types and logic
type Wrapper struct {
	Auth pkg.AuthClient
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

	// convert generated api format to internal struct
	sessionRequest := pkg.CreateSessionRequest{
		Type:        pkg.ContractType(params.Type),
		Version:     pkg.Version(params.Version),
		Language:    pkg.Language(params.Language),
		LegalEntity: string(params.LegalEntity),
		ValidFrom:   vf,
		ValidTo:     vt,
	}

	// TODO: make it possible to provide the acting party via a JWT or other secure way
	//actingParty := "Demo EHR"

	// Initiate the actual session
	result, err := api.Auth.CreateContractSession(sessionRequest, "")
	if err != nil {
		if errors.Is(err, pkg.ErrContractNotFound) {
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
		if errors.Is(err, pkg.ErrSessionNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, err.Error())
		}
		return err
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

	nutsAuthToken := string(sessionStatus.NutsAuthToken)
	proofStatus := string(sessionStatus.ProofStatus)

	answer := SessionResult{
		Disclosed: &disclosedAttributes,
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

// ValidateContract first translates the request params to an internal format, it then
// calls the engine's validator and translates the results to the API format and returns
// the answer to the HTTP stack
func (api *Wrapper) ValidateContract(ctx echo.Context) error {
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
		contractLanguage pkg.Language
		contractVersion  pkg.Version
	)
	if params.Language != nil {
		contractLanguage = pkg.Language(*params.Language)
	}

	if params.Version != nil {
		contractVersion = pkg.Version(*params.Version)
	}

	// get contract
	contract, err := api.Auth.ContractByType(pkg.ContractType(contractType), contractLanguage, contractVersion)
	if errors.Is(err, pkg.ErrContractNotFound) {
		return echo.NewHTTPError(http.StatusNotFound, err.Error())
	} else if err != nil {
		return err
	}

	// convert internal data types to generated api types
	answer := Contract{
		Language:           Language(contract.Language),
		Template:           &contract.Template,
		TemplateAttributes: &contract.TemplateAttributes,
		Type:               Type(contract.Type),
		Version:            Version(contract.Version),
	}

	return ctx.JSON(http.StatusOK, answer)
}

func (api *Wrapper) CreateAccessToken(ctx echo.Context) error {
	panic("implement me")
}
