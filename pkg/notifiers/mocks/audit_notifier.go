// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/stackrox/rox/pkg/notifiers (interfaces: AuditNotifier)

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	v1 "github.com/stackrox/rox/generated/api/v1"
	storage "github.com/stackrox/rox/generated/storage"
)

// MockAuditNotifier is a mock of AuditNotifier interface.
type MockAuditNotifier struct {
	ctrl     *gomock.Controller
	recorder *MockAuditNotifierMockRecorder
}

// MockAuditNotifierMockRecorder is the mock recorder for MockAuditNotifier.
type MockAuditNotifierMockRecorder struct {
	mock *MockAuditNotifier
}

// NewMockAuditNotifier creates a new mock instance.
func NewMockAuditNotifier(ctrl *gomock.Controller) *MockAuditNotifier {
	mock := &MockAuditNotifier{ctrl: ctrl}
	mock.recorder = &MockAuditNotifierMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAuditNotifier) EXPECT() *MockAuditNotifierMockRecorder {
	return m.recorder
}

// AuditLoggingEnabled mocks base method.
func (m *MockAuditNotifier) AuditLoggingEnabled() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AuditLoggingEnabled")
	ret0, _ := ret[0].(bool)
	return ret0
}

// AuditLoggingEnabled indicates an expected call of AuditLoggingEnabled.
func (mr *MockAuditNotifierMockRecorder) AuditLoggingEnabled() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AuditLoggingEnabled", reflect.TypeOf((*MockAuditNotifier)(nil).AuditLoggingEnabled))
}

// Close mocks base method.
func (m *MockAuditNotifier) Close(arg0 context.Context) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Close", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// Close indicates an expected call of Close.
func (mr *MockAuditNotifierMockRecorder) Close(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*MockAuditNotifier)(nil).Close), arg0)
}

// IsSecuredClusterNotifier mocks base method.
func (m *MockAuditNotifier) IsSecuredClusterNotifier() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsSecuredClusterNotifier")
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsSecuredClusterNotifier indicates an expected call of IsSecuredClusterNotifier.
func (mr *MockAuditNotifierMockRecorder) IsSecuredClusterNotifier() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsSecuredClusterNotifier", reflect.TypeOf((*MockAuditNotifier)(nil).IsSecuredClusterNotifier))
}

// ProtoNotifier mocks base method.
func (m *MockAuditNotifier) ProtoNotifier() *storage.Notifier {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ProtoNotifier")
	ret0, _ := ret[0].(*storage.Notifier)
	return ret0
}

// ProtoNotifier indicates an expected call of ProtoNotifier.
func (mr *MockAuditNotifierMockRecorder) ProtoNotifier() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ProtoNotifier", reflect.TypeOf((*MockAuditNotifier)(nil).ProtoNotifier))
}

// SendAuditMessage mocks base method.
func (m *MockAuditNotifier) SendAuditMessage(arg0 context.Context, arg1 *v1.Audit_Message) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendAuditMessage", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendAuditMessage indicates an expected call of SendAuditMessage.
func (mr *MockAuditNotifierMockRecorder) SendAuditMessage(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendAuditMessage", reflect.TypeOf((*MockAuditNotifier)(nil).SendAuditMessage), arg0, arg1)
}

// Test mocks base method.
func (m *MockAuditNotifier) Test(arg0 context.Context) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Test", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// Test indicates an expected call of Test.
func (mr *MockAuditNotifierMockRecorder) Test(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Test", reflect.TypeOf((*MockAuditNotifier)(nil).Test), arg0)
}