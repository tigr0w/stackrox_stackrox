// Code generated by MockGen. DO NOT EDIT.
// Source: types.go
//
// Generated by this command:
//
//	mockgen -package mocks -destination mocks/types.go -source types.go
//

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	common "github.com/stackrox/rox/central/views/common"
	images "github.com/stackrox/rox/central/views/images"
	v1 "github.com/stackrox/rox/generated/api/v1"
	gomock "go.uber.org/mock/gomock"
)

// MockImageCore is a mock of ImageCore interface.
type MockImageCore struct {
	ctrl     *gomock.Controller
	recorder *MockImageCoreMockRecorder
	isgomock struct{}
}

// MockImageCoreMockRecorder is the mock recorder for MockImageCore.
type MockImageCoreMockRecorder struct {
	mock *MockImageCore
}

// NewMockImageCore creates a new mock instance.
func NewMockImageCore(ctrl *gomock.Controller) *MockImageCore {
	mock := &MockImageCore{ctrl: ctrl}
	mock.recorder = &MockImageCoreMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockImageCore) EXPECT() *MockImageCoreMockRecorder {
	return m.recorder
}

// GetImageCVEsBySeverity mocks base method.
func (m *MockImageCore) GetImageCVEsBySeverity() common.ResourceCountByCVESeverity {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetImageCVEsBySeverity")
	ret0, _ := ret[0].(common.ResourceCountByCVESeverity)
	return ret0
}

// GetImageCVEsBySeverity indicates an expected call of GetImageCVEsBySeverity.
func (mr *MockImageCoreMockRecorder) GetImageCVEsBySeverity() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetImageCVEsBySeverity", reflect.TypeOf((*MockImageCore)(nil).GetImageCVEsBySeverity))
}

// GetImageID mocks base method.
func (m *MockImageCore) GetImageID() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetImageID")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetImageID indicates an expected call of GetImageID.
func (mr *MockImageCoreMockRecorder) GetImageID() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetImageID", reflect.TypeOf((*MockImageCore)(nil).GetImageID))
}

// MockImageView is a mock of ImageView interface.
type MockImageView struct {
	ctrl     *gomock.Controller
	recorder *MockImageViewMockRecorder
	isgomock struct{}
}

// MockImageViewMockRecorder is the mock recorder for MockImageView.
type MockImageViewMockRecorder struct {
	mock *MockImageView
}

// NewMockImageView creates a new mock instance.
func NewMockImageView(ctrl *gomock.Controller) *MockImageView {
	mock := &MockImageView{ctrl: ctrl}
	mock.recorder = &MockImageViewMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockImageView) EXPECT() *MockImageViewMockRecorder {
	return m.recorder
}

// Get mocks base method.
func (m *MockImageView) Get(ctx context.Context, q *v1.Query) ([]images.ImageCore, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", ctx, q)
	ret0, _ := ret[0].([]images.ImageCore)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Get indicates an expected call of Get.
func (mr *MockImageViewMockRecorder) Get(ctx, q any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockImageView)(nil).Get), ctx, q)
}