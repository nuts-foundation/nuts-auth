package auth

import (
	"encoding/json"
	"fmt"
	"github.com/go-chi/chi"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/irmaserver"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"time"
)

// IrmaInterface allows mocking the irma server during tests
type IrmaInterface interface {
	StartSession(interface{}, irmaserver.SessionHandler) (*irma.Qr, string, error)
	HandlerFunc() http.HandlerFunc
}

type API struct {
	irmaServer IrmaInterface
	irmaConfig *irma.Configuration
}

func (api *API) InitIRMA() {

	irmaConfig, err := irma.NewConfiguration("./conf")
	if err != nil {
		logrus.WithError(err).Error("Could not create irma config")
	}

	api.irmaConfig = irmaConfig

	if err := irmaConfig.DownloadDefaultSchemes(); err != nil {
		logrus.WithError(err).Panic("Could not download default schemes")
	}
	configuration := &server.Configuration{
		//TODO: Make IRMA client URL a config variable
		URL:               "https://5f8da8e3.ngrok.io/auth/irmaclient",
		Logger:            logrus.StandardLogger(),
		IrmaConfiguration: irmaConfig,
	}

	logrus.Info("Initializing IRMA library...")
	irmaServer, err := irmaserver.New(configuration)
	if err != nil {
		logrus.WithError(err).Panic("Could not initialize IRMA library:")
	}

	api.irmaServer = irmaServer
}

func New() *API {
	api := &API{}
	api.InitIRMA()
	return api
}

func (api API) Handler() http.Handler {
	r := chi.NewRouter()
	r.Post("/contract/session", api.CreateSessionHandler)
	r.Get("/contract/{type}", api.GetContractHandler)
	r.Post("/contract/validate", api.ValidateContractHandler)
	r.Mount("/irmaclient", api.irmaServer.HandlerFunc())
	return r
}

func (api API) GetContractHandler(writer http.ResponseWriter, request *http.Request) {
	contractType := chi.URLParam(request, "type")
	contract := ContractByType(contractType, "NL")
	contractJson, _ := json.Marshal(contract)
	_, _ = writer.Write(contractJson)
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
	contract := ContractByType(sessionRequest.Type, sessionRequest.Language)
	if contract == nil {
		logMsg := fmt.Sprintf("Could not find contract with type %v", sessionRequest.Type)
		logrus.Info(logMsg)
		http.Error(writer, logMsg, http.StatusBadRequest)
		return
	}
	message, err := contract.RenderTemplate(map[string]string{"acting_party": "Helder", "valid_from": time.Now().Format(time.RFC850), "valid_to": time.Now().Add(time.Minute * 60).Format(time.RFC850)})
	logrus.Infof("contractMessage: %v", message)
	if err != nil {
		logMsg := fmt.Sprintf("Could not render contract template of type %v: %v", contract.Type, err)
		logrus.Error(logMsg)
		http.Error(writer, logMsg, http.StatusBadRequest)
		return
	}
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

	sessionPointer, token, err := api.irmaServer.StartSession(signatureRequest, func(result *server.SessionResult) {
		logrus.Infof("session done, result: %s", server.ToJson(result))
	})

	if err != nil {
		logrus.Panic("error while creating session: ", err)
		http.Error(writer, "Could not create a new session", http.StatusInternalServerError)
	}

	logrus.Infof("session created with token: %s", token)

	jsonSessionPointer, _ := json.Marshal(sessionPointer)
	writer.WriteHeader(http.StatusCreated)
	_, err = writer.Write(jsonSessionPointer)
	if err != nil {
		logrus.Panicf("Write failed: %v", err)
	}
}

type ValidationResultResponse struct {
	ValidationResult    string                     `json:"validation_result"`
	DisclosedAttributes []*irma.DisclosedAttribute `json:"disclosed_attributes"`
}

func (api *API) ValidateContractHandler(writer http.ResponseWriter, r *http.Request) {
	var signedContract irma.SignedMessage
	body, err := ioutil.ReadAll(r.Body)
	logrus.Infof("Contract validation request for: %v", string(body))
	if err != nil {
		logrus.WithError(err).Error("Could not validate contract. Unable to read body")
		http.Error(writer, "Could not read body", http.StatusBadRequest)
		return
	}
	if err := json.Unmarshal(body, &signedContract); err != nil {
		logMsg := fmt.Sprint("Could not decode json payload")
		logrus.WithError(err).Info(logMsg)
		http.Error(writer, logMsg, http.StatusBadRequest)
		return
	}
	logrus.Info(signedContract)
	attributes, status, err := signedContract.Verify(api.irmaConfig, nil)
	if err != nil {
		logMsg := "Unable to verify contract"
		logrus.WithError(err).Info(logMsg)
		http.Error(writer, logMsg, http.StatusBadRequest)
		return
	}

	jsonResult, err := json.Marshal(
		ValidationResultResponse{
			ValidationResult:    string(status),
			DisclosedAttributes: attributes,
		})
	if err != nil {
		logrus.WithError(err).Error("Could not marshall json response in ValidateContractHandler")
	}
	_, _ = writer.Write(jsonResult)
}