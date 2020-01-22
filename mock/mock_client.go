// Code generated by MockGen. DO NOT EDIT.
// Source: pkg/auth.go

// Package mock is a generated GoMock package.
package mock

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	pkg "github.com/nuts-foundation/nuts-auth/pkg"
)

// MockAuthClient is a mock of AuthClient interface
type MockAuthClient struct {
	ctrl     *gomock.Controller
	recorder *MockAuthClientMockRecorder
}

// MockAuthClientMockRecorder is the mock recorder for MockAuthClient
type MockAuthClientMockRecorder struct {
	mock *MockAuthClient
}

// NewMockAuthClient creates a new mock instance
func NewMockAuthClient(ctrl *gomock.Controller) *MockAuthClient {
	mock := &MockAuthClient{ctrl: ctrl}
	mock.recorder = &MockAuthClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockAuthClient) EXPECT() *MockAuthClientMockRecorder {
	return m.recorder
}

// CreateContractSession mocks base method
func (m *MockAuthClient) CreateContractSession(sessionRequest pkg.CreateSessionRequest, actingParty string) (*pkg.CreateSessionResult, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateContractSession", sessionRequest, actingParty)
	ret0, _ := ret[0].(*pkg.CreateSessionResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateContractSession indicates an expected call of CreateContractSession
func (mr *MockAuthClientMockRecorder) CreateContractSession(sessionRequest, actingParty interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateContractSession", reflect.TypeOf((*MockAuthClient)(nil).CreateContractSession), sessionRequest, actingParty)
}

// ContractSessionStatus mocks base method
func (m *MockAuthClient) ContractSessionStatus(sessionID string) (*pkg.SessionStatusResult, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ContractSessionStatus", sessionID)
	ret0, _ := ret[0].(*pkg.SessionStatusResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ContractSessionStatus indicates an expected call of ContractSessionStatus
func (mr *MockAuthClientMockRecorder) ContractSessionStatus(sessionID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ContractSessionStatus", reflect.TypeOf((*MockAuthClient)(nil).ContractSessionStatus), sessionID)
}

// ContractByType mocks base method
func (m *MockAuthClient) ContractByType(contractType pkg.ContractType, language pkg.Language, version pkg.Version) (*pkg.Contract, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ContractByType", contractType, language, version)
	ret0, _ := ret[0].(*pkg.Contract)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ContractByType indicates an expected call of ContractByType
func (mr *MockAuthClientMockRecorder) ContractByType(contractType, language, version interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ContractByType", reflect.TypeOf((*MockAuthClient)(nil).ContractByType), contractType, language, version)
}

// ValidateContract mocks base method
func (m *MockAuthClient) ValidateContract(request pkg.ValidationRequest) (*pkg.ContractValidationResult, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ValidateContract", request)
	ret0, _ := ret[0].(*pkg.ContractValidationResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ValidateContract indicates an expected call of ValidateContract
func (mr *MockAuthClientMockRecorder) ValidateContract(request interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ValidateContract", reflect.TypeOf((*MockAuthClient)(nil).ValidateContract), request)
}

// ParseAndValidateJwtBearerToken mocks base method
func (m *MockAuthClient) CreateAccessToken(request pkg.CreateAccessTokenRequest) (*pkg.AccessTokenResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ParseAndValidateJwtBearerToken", request)
	ret0, _ := ret[0].(*pkg.AccessTokenResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ParseAndValidateJwtBearerToken indicates an expected call of ParseAndValidateJwtBearerToken
func (mr *MockAuthClientMockRecorder) CreateAccessToken(request interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ParseAndValidateJwtBearerToken", reflect.TypeOf((*MockAuthClient)(nil).CreateAccessToken), request)
}
