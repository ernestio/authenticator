/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package authenticator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthenticate(t *testing.T) {

	authenticateTests := []struct {
		username string
		password string
		provider string
		exists   bool
		expected error
	}{
		{"valid-local-user", "secret", "local", true, nil},
		{"valid-local-user-bad-password", "wrong", "local", true, ErrUnauthorized},
		{"invalid-local-user", "secret", "local", false, ErrUnauthorized},
		{"valid-federation-new-user", "secret", "federation", false, nil},
		{"valid-federation-new-user-bad-password", "wrong", "federation", false, ErrUnauthorized},
		{"valid-federation-existing-user", "secret", "federation", true, nil},
		{"valid-federation-existing-user-bad-password", "wrong", "federation", true, ErrUnauthorized},
		{"invalid-federation-user", "secret", "federation", false, ErrUnauthorized},
	}

	for _, tt := range authenticateTests {
		t.Run(tt.username, func(t *testing.T) {
			Auth := New([]string{"local", "federation"}, "secret")
			Auth.Conn = NewFakeConnector()
			c := Credentials{
				Username: tt.username,
				Password: tt.password,
			}
			conn := Auth.Conn.(*FakeConnector)
			_, err := Auth.Authenticate(c)
			assert := assert.New(t)
			assert.Equal(err, tt.expected)

			if tt.expected == nil {
				if tt.exists && tt.provider == "local" {
					assert.Equal(len(conn.Events["user.get"]), 1)
				} else if tt.exists && tt.provider == "federation" {
					assert.Equal(len(conn.Events["user.get"]), 2)
					assert.Equal(len(conn.Events["federation.auth"]), 1)
				}
			}

			// if tt.username == "valid-federation-existing-user" {
			// 	if len(conn.Events["user.get"]) != 2 {
			// 		t.Errorf("Expected 2 user.get message, got '%d' ", len(conn.Events["user.get"]))
			// 	}
			// 	if len(conn.Events["federation.auth"]) != 1 {
			// 		t.Errorf("Expected 1 federation.auth message, got '%d' ", len(conn.Events["federation.auth"]))
			// 	}
			// }
			// if tt.username == "valid-federation-new-user" {
			// 	if len(conn.Events["user.get"]) != 2 {
			// 		t.Errorf("Expected 2 user.get message, got '%d' ", len(conn.Events["user.get"]))
			// 	}
			// 	if len(conn.Events["federation.auth"]) != 1 {
			// 		t.Errorf("Expected 1 federation.auth message, got '%d' ", len(conn.Events["federation.auth"]))
			// 	}
			// 	if len(conn.Events["user.set"]) != 1 {
			// 		t.Errorf("Expected 1 user.set message, got '%d' ", len(conn.Events["user.set"]))
			// 	}
			// }
		})
	}
}
