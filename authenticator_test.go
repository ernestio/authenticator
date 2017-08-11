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
		auth, conn := testsetup()

		c := Credentials{
			Username: tt.username,
			Password: tt.password,
		}

		t.Run(name, func(t *testing.T) {
			token, err := auth.Authenticate(c)
			assert.Equal(t, err, tt.expected)

			if tt.expected != nil {
				return
			}

			assert.NotNil(t, token)

			if tt.provider == "local" {
				assert.Equal(t, len(conn.Events["user.get"]), 1)
				return
			}

			assert.Equal(t, len(conn.Events["user.get"]), 2)
			assert.Equal(t, len(conn.Events["federation.auth"]), 1)

			if !tt.exists {
				assert.Equal(t, len(conn.Events["user.set"]), 1)
				assert.Equal(t, string(conn.Events["user.set"][0].Data), `{"username": "valid-federation-new-user", "type": "federation"}`)
			}
		})
	}
}
