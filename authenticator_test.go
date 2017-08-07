/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package authenticator

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/nats-io/nats"
	"github.com/stretchr/testify/suite"
)

type FakeConnector struct{}

func (f *FakeConnector) Request(subj string, data []byte, timeout time.Duration) (*nats.Msg, error) {
	var c Credentials

	err := json.Unmarshal(data, &c)
	if err != nil {
		return &nats.Msg{Data: []byte(`{"error": "could not load credentials"}`)}, nil
	}

	// remove
	if c["username"] == "john" {
		return &nats.Msg{Data: []byte(`{"ok": true}`)}, nil
	}

	return &nats.Msg{Data: []byte(`{"ok": false}`)}, nil
}

// AuthenticatorTestSuite : Test suite for migration
type AuthenticatorTestSuite struct {
	suite.Suite
	Auth       *Authenticator
	Assertions []struct {
		Name               string
		Username, Password string
		Expected           error
	}
}

// SetupTest : sets up test suite
func (suite *AuthenticatorTestSuite) SetupTest() {
	suite.Auth = New([]string{"fake"})
	suite.Auth.Conn = &FakeConnector{}
	suite.Assertions = []struct {
		Name               string
		Username, Password string
		Expected           error
	}{
		{"invalid user", "bad-user", "password", ErrUnauthorized},
		{"valid user", "john", "password", nil},
	}
}

func (suite *AuthenticatorTestSuite) TestAuthSingleProvider() {
	for _, scenario := range suite.Assertions {
		suite.T().Run(scenario.Name, func(t *testing.T) {
			c := Credentials{
				"username": scenario.Username,
				"password": scenario.Password,
			}
			err := suite.Auth.Authenticate(c)
			suite.Equal(err, scenario.Expected)
		})
	}
}

// TestAuthenticatorTestSuite : Test suite for migration
func TestAuthenticatorTestSuite(t *testing.T) {
	suite.Run(t, new(AuthenticatorTestSuite))
}
