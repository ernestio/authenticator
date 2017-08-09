/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package authenticator

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

// AuthenticatorTestSuite : Test suite
type AuthenticatorTestSuite struct {
	suite.Suite
	Auth       *Authenticator
	Assertions []struct {
		Name     string
		Username string
		Password string
		Exists   bool
		Expected error
	}
}

// SetupTest : Test suite setup
func (suite *AuthenticatorTestSuite) SetupTest() {
	suite.Auth = New([]string{"local", "fake"})
	suite.Auth.Conn = NewFakeConnector()
	suite.Assertions = []struct {
		Name     string
		Username string
		Password string
		Exists   bool
		Expected error
	}{
		{"valid existing user", "john", "secret", true, nil},
		{"valid new user", "jane", "secret", false, nil},
		{"invalid user", "bad-user", "password", false, ErrUnauthorized},
	}
}

// TestAuthProviders : Tests authentication against a list of providers
func (suite *AuthenticatorTestSuite) TestAuthProviders() {
	for _, scenario := range suite.Assertions {
		suite.SetupTest()
		suite.T().Run(scenario.Name, func(t *testing.T) {
			c := Credentials{
				"username": scenario.Username,
				"password": scenario.Password,
			}
			conn := suite.Auth.Conn.(*FakeConnector)
			err := suite.Auth.Authenticate(c)
			suite.Equal(err, scenario.Expected)
			if scenario.Expected == nil {
				suite.Equal(len(conn.Events["user.get"]), 1)
				if !scenario.Exists {
					suite.Equal(len(conn.Events["user.set"]), 1)
				}
			}
		})
	}
}

// TestAuthenticatorTestSuite : Run test suite
func TestAuthenticatorTestSuite(t *testing.T) {
	suite.Run(t, new(AuthenticatorTestSuite))
}
