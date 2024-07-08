package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		expectedKey string
		expectedErr error
	}{
		{
			name:        "valid header",
			headers:     http.Header{"Authorization": {"ApiKey abc123"}},
			expectedKey: "abc123",
			expectedErr: nil,
		},
		{
			name:        "missing authorization header",
			headers:     http.Header{},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:        "malformed authorization header",
			headers:     http.Header{"Authorization": {"Bearer abc123"}},
			expectedKey: "",
			expectedErr: ErrMalformedAuthorizationHeader,
		},
		{
			name:        "empty authorization header",
			headers:     http.Header{"Authorization": {""}},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:        "missing ApiKey in authorization header",
			headers:     http.Header{"Authorization": {"ApiKey"}},
			expectedKey: "",
			expectedErr: ErrMalformedAuthorizationHeader,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)
			if key != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, key)
			}
			if !errors.Is(err, tt.expectedErr) {
				t.Errorf("expected error %v, got %v", tt.expectedErr, err)
			}
		})
	}
}
