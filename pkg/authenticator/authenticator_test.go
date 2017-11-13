/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package authenticator

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthenticate(t *testing.T) {
	tests := map[string]struct {
		username string
		password string
		admin    bool
		provider string
		exists   bool
		expected error
	}{
		"valid local user":                            {"valid-local-user", "secret", false, "local", true, nil},
		"valid-local-user-bad-password":               {"valid-local-user-bad-password", "wrong", false, "local", true, ErrUnauthorized},
		"invalid-local-user":                          {"invalid-local-user", "secret", false, "local", false, ErrUnauthorized},
		"valid-federation-new-user":                   {"valid-federation-new-user", "secret", false, "federation", false, nil},
		"valid-federation-new-user-bad-password":      {"valid-federation-new-user-bad-password", "wrong", false, "federation", false, ErrUnauthorized},
		"valid-federation-new-admin-user":             {"valid-federation-new-admin-user", "secret", true, "federation", false, nil},
		"valid-federation-existing-user":              {"valid-federation-existing-user", "secret", false, "federation", true, nil},
		"valid-federation-existing-user-bad-password": {"valid-federation-existing-user-bad-password", "wrong", false, "federation", true, ErrUnauthorized},
		"valid-federation-existing-admin-user":        {"valid-federation-existing-admin-user", "secret", true, "federation", true, nil},
		"invalid-federation-user":                     {"invalid-federation-user", "secret", false, "federation", false, ErrUnauthorized},
	}

	for name, tt := range tests {
		auth, conn := testSetup()

		c := Credentials{
			Username: tt.username,
			Password: tt.password,
		}

		t.Run(name, func(t *testing.T) {
			token, err := auth.Authenticate(c)
			assert := assert.New(t)

			assert.Equal(err, tt.expected)

			if tt.expected != nil {
				return
			}

			assert.NotNil(token)

			if tt.provider == "local" {
				assert.Equal(len(conn.Events["user.get"]), 1)
				return
			}

			assert.Equal(len(conn.Events["user.get"]), 2)
			assert.Equal(len(conn.Events["federation.auth"]), 1)

			if tt.provider == "federation" {
				assert.Equal(len(conn.Events["user.set"]), 1)
				if tt.exists {
					if tt.admin {
						assert.Equal(string(conn.Events["user.set"][0].Data), `{"username": "valid-federation-existing-admin-user", "type": "federation", "admin": true}`)
					} else {
						assert.Equal(string(conn.Events["user.set"][0].Data), `{"username": "valid-federation-existing-user", "type": "federation", "admin": false}`)
					}
				} else {
					if tt.admin {
						assert.Equal(string(conn.Events["user.set"][0].Data), `{"username": "valid-federation-new-admin-user", "type": "federation", "admin": true}`)
					} else {
						assert.Equal(string(conn.Events["user.set"][0].Data), `{"username": "valid-federation-new-user", "type": "federation", "admin": false}`)
					}
				}
			}
		})
	}
}

func TestVerifyMFA(t *testing.T) {
	tests := map[string]struct {
		username         string
		verificationCode string
		expected         error
	}{
		"valid MFA verfication":    {"john", "secret", nil},
		"invalid MFA verification": {"jane", "wrong", errors.New("verification failed")},
	}

	for name, tt := range tests {
		auth, _ := testSetup()

		c := Credentials{
			Username:         tt.username,
			VerificationCode: tt.verificationCode,
		}

		t.Run(name, func(t *testing.T) {
			err := auth.verifyMFA(c)
			assert := assert.New(t)

			assert.Equal(err, tt.expected)

			if tt.expected != nil {
				return
			}
		})
	}
}
