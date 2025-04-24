package postgresql

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"
)

// TestParseStartupMessage tests the parseStartupMessage function
func TestParseStartupMessage(t *testing.T) {
	// Test cases will be added here
	p := &PostgresProxy{} // Dummy proxy instance

	tests := []struct {
		name            string
		inputParams     map[string]string
		protocolVersion uint32
		expectError     bool
		expectedParams  map[string]string
	}{
		{
			name: "Valid standard startup message",
			inputParams: map[string]string{
				"user":     "testuser",
				"database": "testdb",
			},
			protocolVersion: 196608, // 3.0
			expectError:     false,
			expectedParams: map[string]string{
				"user":     "testuser",
				"database": "testdb",
			},
		},
		{
			name: "Valid startup message with extra params",
			inputParams: map[string]string{
				"user":             "anotheruser",
				"database":         "anotherdb",
				"application_name": "my_app",
				"client_encoding":  "UTF8",
			},
			protocolVersion: 196608,
			expectError:     false,
			expectedParams: map[string]string{
				"user":             "anotheruser",
				"database":         "anotherdb",
				"application_name": "my_app",
				"client_encoding":  "UTF8",
			},
		},
		{
			name:            "Empty parameters",
			inputParams:     map[string]string{},
			protocolVersion: 196608,
			expectError:     false,
			expectedParams:  map[string]string{},
		},
		{
			name: "Invalid protocol version (but parse should still work)",
			inputParams: map[string]string{
				"user": "testuser",
			},
			protocolVersion: 12345, // Invalid version
			expectError:     false, // Parse function itself shouldn't error on version
			expectedParams: map[string]string{
				"user": "testuser",
			},
		},
		// Add more test cases for malformed packets if needed
		// For example, missing null terminators (harder to simulate without manual byte manipulation)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dummyMessage := createDummyStartupMessage(tt.inputParams, tt.protocolVersion)
			reader := bytes.NewReader(dummyMessage)

			parsedParams, err := p.parseStartupMessage(reader)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected an error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("did not expect an error but got: %v", err)
				}
				if parsedParams == nil {
					t.Errorf("expected params but got nil")
					return // Avoid nil pointer dereference below
				}
				if parsedParams.ProtocolVersion != tt.protocolVersion {
					t.Errorf("expected protocol version %d, got %d", tt.protocolVersion, parsedParams.ProtocolVersion)
				}
				if !reflect.DeepEqual(parsedParams.Parameters, tt.expectedParams) {
					t.Errorf("expected parameters %v, got %v", tt.expectedParams, parsedParams.Parameters)
				}
				// Check if RawMessage is reconstructed correctly
				if !bytes.Equal(parsedParams.RawMessage, dummyMessage) {
					t.Errorf("RawMessage does not match original message.\nExpected: %x\nGot:      %x", dummyMessage, parsedParams.RawMessage)
				}
			}
		})
	}
}

// TestValidateAndModifyUsername tests the validateAndModifyUsername function
func TestValidateAndModifyUsername(t *testing.T) {
	// Test cases will be added here
}

// Helper function to create a dummy startup message
func createDummyStartupMessage(params map[string]string, protocolVersion uint32) []byte {
	totalLength := 4 + 4 // Length field + protocol version
	for key, value := range params {
		totalLength += len(key) + 1 + len(value) + 1
	}
	totalLength++ // Final null byte

	msg := make([]byte, totalLength)
	binary.BigEndian.PutUint32(msg[0:4], uint32(totalLength))
	binary.BigEndian.PutUint32(msg[4:8], protocolVersion)

	offset := 8
	for key, value := range params {
		copy(msg[offset:], key)
		offset += len(key)
		msg[offset] = 0
		offset++
		copy(msg[offset:], value)
		offset += len(value)
		msg[offset] = 0
		offset++
	}
	msg[offset] = 0
	return msg
}
