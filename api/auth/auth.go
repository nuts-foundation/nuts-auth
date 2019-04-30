package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-chi/chi"
	"github.com/nuts-foundation/nuts-proxy/auth"
	"github.com/nuts-foundation/nuts-proxy/configuration"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"time"
)

type API struct {
	authValidator auth.Validator
	configuration *configuration.NutsProxyConfiguration
}

func New(config *configuration.NutsProxyConfiguration, authService auth.Validator) *API {
	api := &API{
		authValidator: authService,
		configuration: config,
	}
	return api
}

func (api API) Handler() http.Handler {
	r := chi.NewRouter()
	r.Route("/contract", func(r chi.Router) {
		r.Use(ServiceProviderCtxFn(api.configuration))
		r.Post("/session", api.CreateSessionHandler)
		r.Get("/session/{sessionId}", api.GetSessionStatusHandler)
		r.Get("/{type}", api.GetContractHandler)
	})
	r.Post("/contract/validate", api.ValidateContractHandler)
	return r
}

type SessionStatus struct {
	Status string `json:"status"`
}

// ActingPartyKey is the key that holds the common name of the current acting party in the request context.
const ActingPartyKey = "actingParty"

func ServiceProviderCtxFn(config *configuration.NutsProxyConfiguration) func(http.Handler) http.Handler {
	actingParty := config.ActingPartyCN

	return func(next http.Handler) http.Handler {

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if actingParty == "" {
				http.Error(w, "Unknown acting party", http.StatusForbidden)
				return
			}
			ctx := context.WithValue(r.Context(), ActingPartyKey, actingParty)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (api API) GetSessionStatusHandler(writer http.ResponseWriter, r *http.Request) {
	sessionId := auth.SessionId(chi.URLParam(r, "sessionId"))
	sessionResult := api.authValidator.SessionStatus(sessionId)
	if sessionResult == nil {
		http.Error(writer, "Session not found", http.StatusNotFound)
		return
	}
	statusJson, _ := json.Marshal(sessionResult)
	_, _ = writer.Write(statusJson)
}

func (api API) GetContractHandler(writer http.ResponseWriter, request *http.Request) {
	contractType := chi.URLParam(request, "type")

	contractLanguage := request.URL.Query().Get("language")
	if contractLanguage == "" {
		contractLanguage = "NL"
	}

	contractVersion := request.URL.Query().Get("version")

	contract := ContractByType(contractType, contractLanguage, contractVersion)
	if contract == nil {
		http.Error(writer, "could not find contract with this type, language and version", http.StatusNotFound)
		return
	}
	contractJson, _ := json.Marshal(contract)
	_, _ = writer.Write(contractJson)
}

type CreateSessionResult struct {
	QrCodeInfo irma.Qr `json:"qr_code_info"`
	SessionId  string  `json:"session_id"`
}

func (api API) CreateSessionHandler(writer http.ResponseWriter, r *http.Request) {
	var sessionRequest ContractSigningRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&sessionRequest); err != nil {
		logMsg := fmt.Sprintf("Could not decode json request parameters %v", r.Body)
		logrus.Info(logMsg)
		http.Error(writer, logMsg, http.StatusBadRequest)
		return
	}
	contract := ContractByType(sessionRequest.Type, sessionRequest.Language, sessionRequest.Version)
	if contract == nil {
		logMsg := fmt.Sprintf("Could not find contract with type %v", sessionRequest.Type)
		logrus.Info(logMsg)
		http.Error(writer, logMsg, http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	actingParty, ok := ctx.Value(ActingPartyKey).(string)
	if !ok {
		// This should not happen since the context provides us with the value and does its own error handling
		http.Error(writer, http.StatusText(422), 422)
		return
	}

	message, err := contract.RenderTemplate(map[string]string{
		"acting_party": actingParty,
	}, 0, 60*time.Minute)
	logrus.Infof("contractMessage: %v", message)
	if err != nil {
		logMsg := fmt.Sprintf("Could not render contract template of type %v: %v", contract.Type, err)
		logrus.Error(logMsg)
		http.Error(writer, logMsg, http.StatusBadRequest)
		return
	}
	// TODO: put this in a separate service
	signatureRequest := &irma.SignatureRequest{
		Message: message,
		DisclosureRequest: irma.DisclosureRequest{
			BaseRequest: irma.BaseRequest{
				Type: irma.ActionSigning,
			},
			Content: irma.AttributeDisjunctionList([]*irma.AttributeDisjunction{{
				Label:      "AGB-Code",
				Attributes: []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier(contract.SignerAttributes[0])},
			}}),
		},
	}

	sessionPointer, token, err := api.authValidator.StartSession(signatureRequest, func(result *server.SessionResult) {
		logrus.Infof("session done, result: %s", server.ToJson(result))
	})
	if err != nil {
		logrus.Panic("error while creating session: ", err)
		http.Error(writer, "Could not create a new session", http.StatusInternalServerError)
	}

	logrus.Infof("session created with token: %s", token)

	//jsonSessionPointer, _ := json.Marshal(sessionPointer)
	createSessionResult := CreateSessionResult{
		QrCodeInfo: *sessionPointer,
		SessionId:  token,
	}
	createSessionResultJson, _ := json.Marshal(createSessionResult)
	writer.WriteHeader(http.StatusCreated)
	_, err = writer.Write(createSessionResultJson)
	if err != nil {
		logrus.Panicf("Write failed: %v", err)
	}
}

type ValidationRequest struct {
	// ContractFormat specifies the type of format used for the contract, e.g. 'irma'
	ContractFormat string `json:"contract_format"`
	// The actual contract in string format to validate
	ContractString string `json:"contract_string"`
	// ActingPartyCN is the common name of the Acting party extracted from the client cert
	ActingPartyCN string `json:"acting_party_cn"`
}

type ValidationResultResponse struct {
	ValidationResult    string                     `json:"validation_result"`
	DisclosedAttributes []*irma.DisclosedAttribute `json:"disclosed_attributes"`
}

func (api *API) ValidateContractHandler(writer http.ResponseWriter, r *http.Request) {
	var validationRequest ValidationRequest

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		logrus.WithError(err).Error("Could not validate contract. Unable to read body")
		http.Error(writer, "Could not read body", http.StatusBadRequest)
		return
	}
	if err := json.Unmarshal(body, &validationRequest); err != nil {
		logMsg := fmt.Sprint("Could not decode json payload")
		logrus.WithError(err).Info(logMsg)
		http.Error(writer, logMsg, http.StatusBadRequest)
		return
	}
	logrus.Debug(validationRequest)
	validationResponse, err := api.authValidator.ValidateContract(validationRequest.ContractString, auth.ContractFormat(validationRequest.ContractFormat), validationRequest.ActingPartyCN)
	if err != nil {
		//logMsg := "Unable to verify contract"
		logrus.WithError(err).Info(err.Error())
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	jsonResult, err := json.Marshal(validationResponse)
	if err != nil {
		logrus.WithError(err).Error("Could not marshall json response in ValidateContractHandler")
	}
	_, _ = writer.Write(jsonResult)
}
