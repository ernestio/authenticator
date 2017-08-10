/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package authenticator

import (
	"fmt"
	"testing"
)

func TestAuthenticate(t *testing.T) {

	authenticateTests := []struct {
		username string
		password string
		exists   bool
		expected error
	}{
		{"valid-local-user", "secret", true, nil},
		{"valid-local-user-bad-password", "wrong", true, ErrUnauthorized},
		{"invalid-local-user", "secret", false, ErrUnauthorized},
		{"valid-federation-new-user", "secret", false, nil},
		{"valid-federation-new-user-bad-password", "wrong", false, ErrUnauthorized},
		{"valid-federation-existing-user", "secret", true, nil},
		{"valid-federation-existing-user-bad-password", "wrong", true, ErrUnauthorized},
		{"invalid-federation-user", "secret", true, ErrUnauthorized},
	}

	for _, tt := range authenticateTests {
		t.Run(tt.username, func(t *testing.T) {
			Auth := New([]string{"local", "federation"})
			Auth.Conn = NewFakeConnector()
			c := Credentials{
				Username: tt.username,
				Password: tt.password,
			}
			conn := Auth.Conn.(*FakeConnector)
			token, err := Auth.Authenticate(c)
			fmt.Println(token)
			if err != tt.expected {
				t.Errorf("Expected '%s' to be '%v', got '%s'", tt.username, tt.expected, err)
			}
			fmt.Println(conn.Events)
			if tt.username == "valid-local-user" {
				if len(conn.Events["user.get"]) != 1 {
					t.Errorf("Expected 1 user.get message, got '%d' ", len(conn.Events["user.get"]))
				}
			}
			if tt.username == "valid-federation-existing-user" {
				if len(conn.Events["user.get"]) != 2 {
					t.Errorf("Expected 2 user.get message, got '%d' ", len(conn.Events["user.get"]))
				}
				if len(conn.Events["federation.auth"]) != 1 {
					t.Errorf("Expected 1 federation.auth message, got '%d' ", len(conn.Events["federation.auth"]))
				}
			}
			if tt.username == "valid-federation-new-user" {
				if len(conn.Events["user.get"]) != 2 {
					t.Errorf("Expected 2 user.get message, got '%d' ", len(conn.Events["user.get"]))
				}
				if len(conn.Events["federation.auth"]) != 1 {
					t.Errorf("Expected 1 federation.auth message, got '%d' ", len(conn.Events["federation.auth"]))
				}
				if len(conn.Events["user.set"]) != 1 {
					t.Errorf("Expected 1 user.set message, got '%d' ", len(conn.Events["user.set"]))
				}
			}
		})
	}
}
