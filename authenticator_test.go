/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package authenticator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthenticate(t *testing.T) {

	tests := map[string]struct {
		username string
		password string
		provider string
		exists   bool
		expected error
	}{
		"valid local user":                            {"valid-local-user", "secret", "local", true, nil},
		"valid-local-user-bad-password":               {"valid-local-user-bad-password", "wrong", "local", true, ErrUnauthorized},
		"invalid-local-user":                          {"invalid-local-user", "secret", "local", false, ErrUnauthorized},
		"valid-federation-new-user":                   {"valid-federation-new-user", "secret", "federation", false, nil},
		"valid-federation-new-user-bad-password":      {"valid-federation-new-user-bad-password", "wrong", "federation", false, ErrUnauthorized},
		"valid-federation-existing-user":              {"valid-federation-existing-user", "secret", "federation", true, nil},
		"valid-federation-existing-user-bad-password": {"valid-federation-existing-user-bad-password", "wrong", "federation", true, ErrUnauthorized},
		"invalid-federation-user":                     {"invalid-federation-user", "secret", "federation", false, ErrUnauthorized},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
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
				switch tt.provider {
				case "local":
					assert.Equal(len(conn.Events["user.get"]), 1)
				case "federation":
					assert.Equal(len(conn.Events["user.get"]), 2)
					assert.Equal(len(conn.Events["federation.auth"]), 1)
					if !tt.exists {
						assert.Equal(len(conn.Events["user.set"]), 1)
					}
				}
			}
		})
	}
}
