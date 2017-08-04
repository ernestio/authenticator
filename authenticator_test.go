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
	Assertions map[string]interface{}
}

// SetupTest : sets up test suite
func (suite *AuthenticatorTestSuite) SetupTest() {
	suite.Auth = New([]string{"fake"})
	suite.Auth.Conn = &FakeConnector{}
	suite.Assertions = map[string]interface{}{
		"invalid user": map[string]interface{}{
			"data": Credentials{"username": "bad-user", "password": "password"}, "error": ErrUnauthorized,
		},
		"valid user": map[string]interface{}{
			"data": Credentials{"username": "john", "password": "password"}, "error": nil,
		},
	}
}

func (suite *AuthenticatorTestSuite) TestAuthSingleProvider() {
	for name, scenario := range suite.Assertions {
		suite.T().Run(name, func(t *testing.T) {
			c := scenario.(map[string]interface{})["data"].(Credentials)
			err := suite.Auth.Authenticate(c)
			suite.Equal(scenario.(map[string]interface{})["error"], err)
		})
	}
}

// TestAuthenticatorTestSuite : Test suite for migration
func TestAuthenticatorTestSuite(t *testing.T) {
	suite.Run(t, new(AuthenticatorTestSuite))
}
