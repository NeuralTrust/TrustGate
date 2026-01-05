package mocks

import (
	"fmt"
	"net/http"

	"github.com/stretchr/testify/mock"
)

type MockHTTPClient struct {
	mock.Mock
}

func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	args := m.Called(req)
	resp, ok := args.Get(0).(*http.Response)
	if !ok && args.Get(0) != nil {
		return nil, fmt.Errorf("expected *http.Response, got %T", args.Get(0))
	}
	return resp, args.Error(1)

}
