/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package authenticator

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/nats-io/nats"
	"github.com/stretchr/testify/suite"
)

type FakeConnector struct{}

func (f *FakeConnector) Request(subj string, data []byte, timeout time.Duration) (*nats.Msg, error) {
	switch subj {
	case "fake.auth":
		return fakeAuth(data)
	case "user.get":
		return userGet(data)
	case "user.create":
		return userCreate(data)
	default:
		return &nats.Msg{Data: []byte(`{"ok": false, "message": "Unknown subject type"}`)}, nil
	}
}

func fakeAuth(data []byte) (*nats.Msg, error) {
	var c Credentials

	err := json.Unmarshal(data, &c)
	if err != nil {
		return &nats.Msg{Data: []byte(`{"ok": false, "message": "Could not load credentials"}`)}, nil
	}

	if c["username"] == "john" && c["password"] == "secret" {
		return &nats.Msg{Data: []byte(`{"ok": true, "token": "xxxx"}`)}, nil
	}

	return &nats.Msg{Data: []byte(`{"ok": false, "message": "Authentication Failed"}`)}, nil
}

func userGet(data []byte) (*nats.Msg, error) {
	var u User

	err := json.Unmarshal(data, &u)
	if err != nil {
		return &nats.Msg{Data: []byte(`{"_error": "Not found", "_code": "404"}`)}, nil
	}

	if u.Username == "john" {
		return &nats.Msg{Data: []byte(`{"username": "john", "password": "xxxx"}`)}, nil
	}

	return &nats.Msg{Data: []byte(`{"_error": "Not found", "_code": "404"}`)}, nil
}

func userCreate(data []byte) (*nats.Msg, error) {
	var u User

	err := json.Unmarshal(data, &u)
	if err != nil {
		return &nats.Msg{Data: []byte(`{"id": 0}`)}, nil
	}

	msg := fmt.Sprintf("{\"username\": \"%s\"}", u.Username)
	return &nats.Msg{Data: []byte(msg)}, nil
}

// AuthenticatorTestSuite : Test suite
type AuthenticatorTestSuite struct {
	suite.Suite
	Auth       *Authenticator
	Assertions []struct {
		Name     string
		Username string
		Password string
		Expected error
	}
}

// SetupTest : Sets up test suite
func (suite *AuthenticatorTestSuite) SetupTest() {
	suite.Auth = New([]string{"fake"})
	suite.Auth.Conn = &FakeConnector{}
	suite.Assertions = []struct {
		Name     string
		Username string
		Password string
		Expected error
	}{
		{"invalid user", "bad-user", "password", ErrUnauthorized},
		{"valid user", "john", "secret", nil},
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

// TestAuthenticatorTestSuite : Run test suite
func TestAuthenticatorTestSuite(t *testing.T) {
	suite.Run(t, new(AuthenticatorTestSuite))
}
