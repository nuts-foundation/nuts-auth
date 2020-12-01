// Code generated by MockGen. DO NOT EDIT.
// Source: pkg/contract/signer.go

// Package mock_contract is a generated GoMock package.
package mock_contract

import (
	gomock "github.com/golang/mock/gomock"
	contract "github.com/nuts-foundation/nuts-auth/pkg/contract"
	reflect "reflect"
)

// MockSigner is a mock of Signer interface
type MockSigner struct {
	ctrl     *gomock.Controller
	recorder *MockSignerMockRecorder
}

// MockSignerMockRecorder is the mock recorder for MockSigner
type MockSignerMockRecorder struct {
	mock *MockSigner
}

// NewMockSigner creates a new mock instance
func NewMockSigner(ctrl *gomock.Controller) *MockSigner {
	mock := &MockSigner{ctrl: ctrl}
	mock.recorder = &MockSignerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockSigner) EXPECT() *MockSignerMockRecorder {
	return m.recorder
}

// SigningSessionStatus mocks base method
func (m *MockSigner) SigningSessionStatus(sessionID string) (contract.SigningSessionResult, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SigningSessionStatus", sessionID)
	ret0, _ := ret[0].(contract.SigningSessionResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SigningSessionStatus indicates an expected call of SigningSessionStatus
func (mr *MockSignerMockRecorder) SigningSessionStatus(sessionID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SigningSessionStatus", reflect.TypeOf((*MockSigner)(nil).SigningSessionStatus), sessionID)
}

// StartSigningSession mocks base method
func (m *MockSigner) StartSigningSession(rawContractText string) (contract.SessionPointer, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StartSigningSession", rawContractText)
	ret0, _ := ret[0].(contract.SessionPointer)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// StartSigningSession indicates an expected call of StartSigningSession
func (mr *MockSignerMockRecorder) StartSigningSession(rawContractText interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StartSigningSession", reflect.TypeOf((*MockSigner)(nil).StartSigningSession), rawContractText)
}

// MockSessionPointer is a mock of SessionPointer interface
type MockSessionPointer struct {
	ctrl     *gomock.Controller
	recorder *MockSessionPointerMockRecorder
}

// MockSessionPointerMockRecorder is the mock recorder for MockSessionPointer
type MockSessionPointerMockRecorder struct {
	mock *MockSessionPointer
}

// NewMockSessionPointer creates a new mock instance
func NewMockSessionPointer(ctrl *gomock.Controller) *MockSessionPointer {
	mock := &MockSessionPointer{ctrl: ctrl}
	mock.recorder = &MockSessionPointerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockSessionPointer) EXPECT() *MockSessionPointerMockRecorder {
	return m.recorder
}

// SessionID mocks base method
func (m *MockSessionPointer) SessionID() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SessionID")
	ret0, _ := ret[0].(string)
	return ret0
}

// SessionID indicates an expected call of SessionID
func (mr *MockSessionPointerMockRecorder) SessionID() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SessionID", reflect.TypeOf((*MockSessionPointer)(nil).SessionID))
}

// Payload mocks base method
func (m *MockSessionPointer) Payload() []byte {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Payload")
	ret0, _ := ret[0].([]byte)
	return ret0
}

// Payload indicates an expected call of Payload
func (mr *MockSessionPointerMockRecorder) Payload() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Payload", reflect.TypeOf((*MockSessionPointer)(nil).Payload))
}

// MarshalJSON mocks base method
func (m *MockSessionPointer) MarshalJSON() ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "MarshalJSON")
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// MarshalJSON indicates an expected call of MarshalJSON
func (mr *MockSessionPointerMockRecorder) MarshalJSON() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "MarshalJSON", reflect.TypeOf((*MockSessionPointer)(nil).MarshalJSON))
}

// MockSigningSessionResult is a mock of SigningSessionResult interface
type MockSigningSessionResult struct {
	ctrl     *gomock.Controller
	recorder *MockSigningSessionResultMockRecorder
}

// MockSigningSessionResultMockRecorder is the mock recorder for MockSigningSessionResult
type MockSigningSessionResultMockRecorder struct {
	mock *MockSigningSessionResult
}

// NewMockSigningSessionResult creates a new mock instance
func NewMockSigningSessionResult(ctrl *gomock.Controller) *MockSigningSessionResult {
	mock := &MockSigningSessionResult{ctrl: ctrl}
	mock.recorder = &MockSigningSessionResultMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockSigningSessionResult) EXPECT() *MockSigningSessionResultMockRecorder {
	return m.recorder
}

// Status mocks base method
func (m *MockSigningSessionResult) Status() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Status")
	ret0, _ := ret[0].(string)
	return ret0
}

// Status indicates an expected call of Status
func (mr *MockSigningSessionResultMockRecorder) Status() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Status", reflect.TypeOf((*MockSigningSessionResult)(nil).Status))
}

// VerifiablePresentation mocks base method
func (m *MockSigningSessionResult) VerifiablePresentation() (contract.VerifiablePresentation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "VerifiablePresentation")
	ret0, _ := ret[0].(contract.VerifiablePresentation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// VerifiablePresentation indicates an expected call of VerifiablePresentation
func (mr *MockSigningSessionResultMockRecorder) VerifiablePresentation() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VerifiablePresentation", reflect.TypeOf((*MockSigningSessionResult)(nil).VerifiablePresentation))
}
