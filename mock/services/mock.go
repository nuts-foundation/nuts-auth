// Code generated by MockGen. DO NOT EDIT.
// Source: pkg/services/services.go

// Package mockservices is a generated GoMock package.
package mockservices

import (
	gomock "github.com/golang/mock/gomock"
	contract "github.com/nuts-foundation/nuts-auth/pkg/contract"
	services "github.com/nuts-foundation/nuts-auth/pkg/services"
	core "github.com/nuts-foundation/nuts-go-core"
	irma "github.com/privacybydesign/irmago"
	server "github.com/privacybydesign/irmago/server"
	http "net/http"
	reflect "reflect"
	time "time"
)

// MockContractValidator is a mock of ContractValidator interface
type MockContractValidator struct {
	ctrl     *gomock.Controller
	recorder *MockContractValidatorMockRecorder
}

// MockContractValidatorMockRecorder is the mock recorder for MockContractValidator
type MockContractValidatorMockRecorder struct {
	mock *MockContractValidator
}

// NewMockContractValidator creates a new mock instance
func NewMockContractValidator(ctrl *gomock.Controller) *MockContractValidator {
	mock := &MockContractValidator{ctrl: ctrl}
	mock.recorder = &MockContractValidatorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockContractValidator) EXPECT() *MockContractValidatorMockRecorder {
	return m.recorder
}

// ValidateContract mocks base method
func (m *MockContractValidator) ValidateContract(contract string, format services.ContractFormat, actingPartyCN *string) (*services.ContractValidationResult, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ValidateContractV0", contract, format, actingPartyCN)
	ret0, _ := ret[0].(*services.ContractValidationResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ValidateContract indicates an expected call of ValidateContract
func (mr *MockContractValidatorMockRecorder) ValidateContract(contract, format, actingPartyCN interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ValidateContractV0", reflect.TypeOf((*MockContractValidator)(nil).ValidateContract), contract, format, actingPartyCN)
}

// ValidateJwt mocks base method
func (m *MockContractValidator) ValidateJwt(contract string, actingPartyCN *string) (*services.ContractValidationResult, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ValidateJwt", contract, actingPartyCN)
	ret0, _ := ret[0].(*services.ContractValidationResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ValidateJwt indicates an expected call of ValidateJwt
func (mr *MockContractValidatorMockRecorder) ValidateJwt(contract, actingPartyCN interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ValidateJwt", reflect.TypeOf((*MockContractValidator)(nil).ValidateJwt), contract, actingPartyCN)
}

// IsInitialized mocks base method
func (m *MockContractValidator) IsInitialized() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsInitialized")
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsInitialized indicates an expected call of IsInitialized
func (mr *MockContractValidatorMockRecorder) IsInitialized() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsInitialized", reflect.TypeOf((*MockContractValidator)(nil).IsInitialized))
}

// MockContractSessionHandler is a mock of ContractSessionHandler interface
type MockContractSessionHandler struct {
	ctrl     *gomock.Controller
	recorder *MockContractSessionHandlerMockRecorder
}

// MockContractSessionHandlerMockRecorder is the mock recorder for MockContractSessionHandler
type MockContractSessionHandlerMockRecorder struct {
	mock *MockContractSessionHandler
}

// NewMockContractSessionHandler creates a new mock instance
func NewMockContractSessionHandler(ctrl *gomock.Controller) *MockContractSessionHandler {
	mock := &MockContractSessionHandler{ctrl: ctrl}
	mock.recorder = &MockContractSessionHandlerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockContractSessionHandler) EXPECT() *MockContractSessionHandlerMockRecorder {
	return m.recorder
}

// SessionStatus mocks base method
func (m *MockContractSessionHandler) SessionStatus(session services.SessionID) (*services.SessionStatusResult, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SessionStatus", session)
	ret0, _ := ret[0].(*services.SessionStatusResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SessionStatus indicates an expected call of SessionStatus
func (mr *MockContractSessionHandlerMockRecorder) SessionStatus(session interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SessionStatus", reflect.TypeOf((*MockContractSessionHandler)(nil).SessionStatus), session)
}

// StartSession mocks base method
func (m *MockContractSessionHandler) StartSession(request interface{}, handler server.SessionHandler) (*irma.Qr, string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StartSession", request, handler)
	ret0, _ := ret[0].(*irma.Qr)
	ret1, _ := ret[1].(string)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// StartSession indicates an expected call of StartSession
func (mr *MockContractSessionHandlerMockRecorder) StartSession(request, handler interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StartSession", reflect.TypeOf((*MockContractSessionHandler)(nil).StartSession), request, handler)
}

// MockOAuthClient is a mock of OAuthClient interface
type MockOAuthClient struct {
	ctrl     *gomock.Controller
	recorder *MockOAuthClientMockRecorder
}

// MockOAuthClientMockRecorder is the mock recorder for MockOAuthClient
type MockOAuthClientMockRecorder struct {
	mock *MockOAuthClient
}

// NewMockOAuthClient creates a new mock instance
func NewMockOAuthClient(ctrl *gomock.Controller) *MockOAuthClient {
	mock := &MockOAuthClient{ctrl: ctrl}
	mock.recorder = &MockOAuthClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockOAuthClient) EXPECT() *MockOAuthClientMockRecorder {
	return m.recorder
}

// CreateAccessToken mocks base method
func (m *MockOAuthClient) CreateAccessToken(request services.CreateAccessTokenRequest) (*services.AccessTokenResult, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateAccessTokenV0", request)
	ret0, _ := ret[0].(*services.AccessTokenResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateAccessToken indicates an expected call of CreateAccessToken
func (mr *MockOAuthClientMockRecorder) CreateAccessToken(request interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateAccessTokenV0", reflect.TypeOf((*MockOAuthClient)(nil).CreateAccessToken), request)
}

// CreateJwtBearerToken mocks base method
func (m *MockOAuthClient) CreateJwtBearerToken(request services.CreateJwtBearerTokenRequest) (*services.JwtBearerTokenResult, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateJwtBearerTokenV0", request)
	ret0, _ := ret[0].(*services.JwtBearerTokenResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateJwtBearerToken indicates an expected call of CreateJwtBearerToken
func (mr *MockOAuthClientMockRecorder) CreateJwtBearerToken(request interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateJwtBearerTokenV0", reflect.TypeOf((*MockOAuthClient)(nil).CreateJwtBearerToken), request)
}

// IntrospectAccessToken mocks base method
func (m *MockOAuthClient) IntrospectAccessToken(token string) (*services.NutsAccessToken, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IntrospectAccessTokenV0", token)
	ret0, _ := ret[0].(*services.NutsAccessToken)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// IntrospectAccessToken indicates an expected call of IntrospectAccessToken
func (mr *MockOAuthClientMockRecorder) IntrospectAccessToken(token interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IntrospectAccessTokenV0", reflect.TypeOf((*MockOAuthClient)(nil).IntrospectAccessToken), token)
}

// Configure mocks base method
func (m *MockOAuthClient) Configure() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Configure")
	ret0, _ := ret[0].(error)
	return ret0
}

// Configure indicates an expected call of Configure
func (mr *MockOAuthClientMockRecorder) Configure() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Configure", reflect.TypeOf((*MockOAuthClient)(nil).Configure))
}

// MockAuthenticationTokenContainerEncoder is a mock of AuthenticationTokenContainerEncoder interface
type MockAuthenticationTokenContainerEncoder struct {
	ctrl     *gomock.Controller
	recorder *MockAuthenticationTokenContainerEncoderMockRecorder
}

// MockAuthenticationTokenContainerEncoderMockRecorder is the mock recorder for MockAuthenticationTokenContainerEncoder
type MockAuthenticationTokenContainerEncoderMockRecorder struct {
	mock *MockAuthenticationTokenContainerEncoder
}

// NewMockAuthenticationTokenContainerEncoder creates a new mock instance
func NewMockAuthenticationTokenContainerEncoder(ctrl *gomock.Controller) *MockAuthenticationTokenContainerEncoder {
	mock := &MockAuthenticationTokenContainerEncoder{ctrl: ctrl}
	mock.recorder = &MockAuthenticationTokenContainerEncoderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockAuthenticationTokenContainerEncoder) EXPECT() *MockAuthenticationTokenContainerEncoderMockRecorder {
	return m.recorder
}

// Decode mocks base method
func (m *MockAuthenticationTokenContainerEncoder) Decode(rawTokenContainer string) (*services.NutsAuthenticationTokenContainer, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Decode", rawTokenContainer)
	ret0, _ := ret[0].(*services.NutsAuthenticationTokenContainer)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Decode indicates an expected call of Decode
func (mr *MockAuthenticationTokenContainerEncoderMockRecorder) Decode(rawTokenContainer interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Decode", reflect.TypeOf((*MockAuthenticationTokenContainerEncoder)(nil).Decode), rawTokenContainer)
}

// Encode mocks base method
func (m *MockAuthenticationTokenContainerEncoder) Encode(authTokenContainer services.NutsAuthenticationTokenContainer) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Encode", authTokenContainer)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Encode indicates an expected call of Encode
func (mr *MockAuthenticationTokenContainerEncoderMockRecorder) Encode(authTokenContainer interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Encode", reflect.TypeOf((*MockAuthenticationTokenContainerEncoder)(nil).Encode), authTokenContainer)
}

// MockSignedToken is a mock of SignedToken interface
type MockSignedToken struct {
	ctrl     *gomock.Controller
	recorder *MockSignedTokenMockRecorder
}

// MockSignedTokenMockRecorder is the mock recorder for MockSignedToken
type MockSignedTokenMockRecorder struct {
	mock *MockSignedToken
}

// NewMockSignedToken creates a new mock instance
func NewMockSignedToken(ctrl *gomock.Controller) *MockSignedToken {
	mock := &MockSignedToken{ctrl: ctrl}
	mock.recorder = &MockSignedTokenMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockSignedToken) EXPECT() *MockSignedTokenMockRecorder {
	return m.recorder
}

// SignerAttributes mocks base method
func (m *MockSignedToken) SignerAttributes() (map[string]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SignerAttributes")
	ret0, _ := ret[0].(map[string]string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SignerAttributes indicates an expected call of SignerAttributes
func (mr *MockSignedTokenMockRecorder) SignerAttributes() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SignerAttributes", reflect.TypeOf((*MockSignedToken)(nil).SignerAttributes))
}

// Contract mocks base method
func (m *MockSignedToken) Contract() contract.Contract {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Contract")
	ret0, _ := ret[0].(contract.Contract)
	return ret0
}

// Contract indicates an expected call of Contract
func (mr *MockSignedTokenMockRecorder) Contract() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Contract", reflect.TypeOf((*MockSignedToken)(nil).Contract))
}

// MockAuthenticationTokenParser is a mock of AuthenticationTokenParser interface
type MockAuthenticationTokenParser struct {
	ctrl     *gomock.Controller
	recorder *MockAuthenticationTokenParserMockRecorder
}

// MockAuthenticationTokenParserMockRecorder is the mock recorder for MockAuthenticationTokenParser
type MockAuthenticationTokenParserMockRecorder struct {
	mock *MockAuthenticationTokenParser
}

// NewMockAuthenticationTokenParser creates a new mock instance
func NewMockAuthenticationTokenParser(ctrl *gomock.Controller) *MockAuthenticationTokenParser {
	mock := &MockAuthenticationTokenParser{ctrl: ctrl}
	mock.recorder = &MockAuthenticationTokenParserMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockAuthenticationTokenParser) EXPECT() *MockAuthenticationTokenParserMockRecorder {
	return m.recorder
}

// Parse mocks base method
func (m *MockAuthenticationTokenParser) Parse(rawAuthToken string) (services.SignedToken, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Parse", rawAuthToken)
	ret0, _ := ret[0].(services.SignedToken)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Parse indicates an expected call of Parse
func (mr *MockAuthenticationTokenParserMockRecorder) Parse(rawAuthToken interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Parse", reflect.TypeOf((*MockAuthenticationTokenParser)(nil).Parse), rawAuthToken)
}

// Verify mocks base method
func (m *MockAuthenticationTokenParser) Verify(token services.SignedToken) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Verify", token)
	ret0, _ := ret[0].(error)
	return ret0
}

// Verify indicates an expected call of Verify
func (mr *MockAuthenticationTokenParserMockRecorder) Verify(token interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Verify", reflect.TypeOf((*MockAuthenticationTokenParser)(nil).Verify), token)
}

// MockContractNotary is a mock of ContractNotary interface
type MockContractNotary struct {
	ctrl     *gomock.Controller
	recorder *MockContractNotaryMockRecorder
}

// MockContractNotaryMockRecorder is the mock recorder for MockContractNotary
type MockContractNotaryMockRecorder struct {
	mock *MockContractNotary
}

// NewMockContractNotary creates a new mock instance
func NewMockContractNotary(ctrl *gomock.Controller) *MockContractNotary {
	mock := &MockContractNotary{ctrl: ctrl}
	mock.recorder = &MockContractNotaryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockContractNotary) EXPECT() *MockContractNotaryMockRecorder {
	return m.recorder
}

// DrawUpContract mocks base method
func (m *MockContractNotary) DrawUpContract(template contract.Template, orgID core.PartyID, validFrom time.Time, validDuration time.Duration) (*contract.Contract, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DrawUpContractV1", template, orgID, validFrom, validDuration)
	ret0, _ := ret[0].(*contract.Contract)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DrawUpContract indicates an expected call of DrawUpContract
func (mr *MockContractNotaryMockRecorder) DrawUpContract(template, orgID, validFrom, validDuration interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DrawUpContractV1", reflect.TypeOf((*MockContractNotary)(nil).DrawUpContract), template, orgID, validFrom, validDuration)
}

// ValidateContract mocks base method
func (m *MockContractNotary) ValidateContract(contractToValidate contract.Contract, orgID core.PartyID, checkTime time.Time) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ValidateContractV0", contractToValidate, orgID, checkTime)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ValidateContract indicates an expected call of ValidateContract
func (mr *MockContractNotaryMockRecorder) ValidateContract(contractToValidate, orgID, checkTime interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ValidateContractV0", reflect.TypeOf((*MockContractNotary)(nil).ValidateContract), contractToValidate, orgID, checkTime)
}

// MockContractClient is a mock of ContractClient interface
type MockContractClient struct {
	ctrl     *gomock.Controller
	recorder *MockContractClientMockRecorder
}

// MockContractClientMockRecorder is the mock recorder for MockContractClient
type MockContractClientMockRecorder struct {
	mock *MockContractClient
}

// NewMockContractClient creates a new mock instance
func NewMockContractClient(ctrl *gomock.Controller) *MockContractClient {
	mock := &MockContractClient{ctrl: ctrl}
	mock.recorder = &MockContractClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockContractClient) EXPECT() *MockContractClientMockRecorder {
	return m.recorder
}

// VerifyVP mocks base method
func (m *MockContractClient) VerifyVP(rawVerifiablePresentation []byte) (*contract.VerificationResult, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "VerifyVP", rawVerifiablePresentation)
	ret0, _ := ret[0].(*contract.VerificationResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// VerifyVP indicates an expected call of VerifyVP
func (mr *MockContractClientMockRecorder) VerifyVP(rawVerifiablePresentation interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VerifyVP", reflect.TypeOf((*MockContractClient)(nil).VerifyVP), rawVerifiablePresentation)
}

// CreateSigningSession mocks base method
func (m *MockContractClient) CreateSigningSession(sessionRequest services.CreateSessionRequest) (contract.SessionPointer, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateSigningSession", sessionRequest)
	ret0, _ := ret[0].(contract.SessionPointer)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateSigningSession indicates an expected call of CreateSigningSession
func (mr *MockContractClientMockRecorder) CreateSigningSession(sessionRequest interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateSigningSession", reflect.TypeOf((*MockContractClient)(nil).CreateSigningSession), sessionRequest)
}

// SigningSessionStatus mocks base method
func (m *MockContractClient) SigningSessionStatus(sessionID string) (contract.SigningSessionResult, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SigningSessionStatus", sessionID)
	ret0, _ := ret[0].(contract.SigningSessionResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SigningSessionStatus indicates an expected call of SigningSessionStatus
func (mr *MockContractClientMockRecorder) SigningSessionStatus(sessionID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SigningSessionStatus", reflect.TypeOf((*MockContractClient)(nil).SigningSessionStatus), sessionID)
}

// Configure mocks base method
func (m *MockContractClient) Configure() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Configure")
	ret0, _ := ret[0].(error)
	return ret0
}

// Configure indicates an expected call of Configure
func (mr *MockContractClientMockRecorder) Configure() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Configure", reflect.TypeOf((*MockContractClient)(nil).Configure))
}

// ContractSessionStatus mocks base method
func (m *MockContractClient) ContractSessionStatus(sessionID string) (*services.SessionStatusResult, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ContractSessionStatus", sessionID)
	ret0, _ := ret[0].(*services.SessionStatusResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ContractSessionStatus indicates an expected call of ContractSessionStatus
func (mr *MockContractClientMockRecorder) ContractSessionStatus(sessionID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ContractSessionStatus", reflect.TypeOf((*MockContractClient)(nil).ContractSessionStatus), sessionID)
}

// ValidateContract mocks base method
func (m *MockContractClient) ValidateContract(request services.ValidationRequest) (*services.ContractValidationResult, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ValidateContractV0", request)
	ret0, _ := ret[0].(*services.ContractValidationResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ValidateContract indicates an expected call of ValidateContract
func (mr *MockContractClientMockRecorder) ValidateContract(request interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ValidateContractV0", reflect.TypeOf((*MockContractClient)(nil).ValidateContract), request)
}

// HandlerFunc mocks base method
func (m *MockContractClient) HandlerFunc() http.HandlerFunc {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "HandlerFunc")
	ret0, _ := ret[0].(http.HandlerFunc)
	return ret0
}

// HandlerFunc indicates an expected call of HandlerFunc
func (mr *MockContractClientMockRecorder) HandlerFunc() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HandlerFunc", reflect.TypeOf((*MockContractClient)(nil).HandlerFunc))
}
