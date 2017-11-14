/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// Package authenticator provides local authentication and authentication
// routing to external providers for the Ernest application.
package authenticator

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

var (
	ErrUnauthorized    = errors.New("Authentication failed")
	supportedProviders = []string{"local", "federation"}
)

// Credentials describes user credentials input
type Credentials struct {
	Username         string `json:"username"`
	Password         string `json:"password"`
	VerificationCode string `json:"verification_code"`
}

// authResponse describes the response for an 'authentication.get' request
type authResponse struct {
	OK      bool   `json:"ok"`
	Admin   bool   `json:"admin"`
	Token   string `json:"token,omitempty"`
	Message string `json:"message,omitempty"`
}

type mfaResponse struct {
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
}

// userResponse describes the response for a 'get' request to user-store
type userResponse struct {
	Code string `json:"_code"`
}

// Authenticator describes the authenticator service and its dependencies
type Authenticator struct {
	Conn      Connector
	Providers Providers     `json:"providers"`
	Secret    string        `json:"secret"`
	Expiry    time.Duration `json:"expiry"`
}

// Providers describes list of providers
type Providers []Provider

// Provider describes an authentication provider
type Provider struct {
	Type   string `json:"type"`
	Config struct {
		URL    string `json:"url,omitemtpy"`
		Scope  string `json:"scope,omitempty"`
		Domain string `json:"domain,omitempty"`
	}
}

// Authenticate validates a users credentials across a list of configured providers
func (a *Authenticator) Authenticate(c Credentials) (*authResponse, error) {
	var err error
	var token *jwt.Token
	var userType string

	for _, provider := range a.Providers {
		token, err = a.auth(provider, c)
		if err == nil {
			userType = provider.Type
			break
		}
	}

	if err != nil {
		return nil, ErrUnauthorized
	}

	if c.VerificationCode != "" {
		err := a.verifyMFA(c)
		if err != nil {
			return nil, err
		}
	}

	// create local user for remote authentication if one doesn't exist
	if userType != "local" {
		claims := token.Claims.(jwt.MapClaims)

		err = a.createUser(c, userType, claims["admin"].(bool))
		if err != nil {
			return nil, err
		}
	}

	tokenString, err := token.SignedString([]byte(a.Secret))
	if err != nil {
		return nil, err
	}

	return &authResponse{OK: true, Token: tokenString}, nil
}

// auth validates user credentials against the specified provider
func (a *Authenticator) auth(p Provider, c Credentials) (*jwt.Token, error) {
	var ar authResponse

	if !a.validProvider(p.Type) {
		log.Println("unknown provider type")
		return nil, errors.New("unknown provider type")
	}

	if p.Type == "local" {
		token, err := a.localAuth(c)
		if err != nil {
			return nil, err
		}
		return token, nil
	}

	data, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}

	resp, err := a.Conn.Request(p.Type+".auth", data, time.Second)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(resp.Data, &ar)
	if err != nil {
		return nil, err
	}

	if ar.OK {
		token := generateToken(c.Username, a.Expiry)
		if ar.Admin {
			token.Claims.(jwt.MapClaims)["admin"] = true
		} else {
			token.Claims.(jwt.MapClaims)["admin"] = false
		}
		return token, nil
	}

	return nil, ErrUnauthorized
}

// validProvider checks the authentication provider type is supported
func (a *Authenticator) validProvider(provider string) bool {
	for _, p := range supportedProviders {
		if p == provider {
			return true
		}
	}
	return false
}

// createUser checks if a user account for the authenticated user already
// exists and if not creates one. Upon creation the authentication provider
// for that user is also set.
func (a *Authenticator) createUser(c Credentials, userType string, admin bool) error {
	var ur userResponse

	data, err := json.Marshal(c)
	if err != nil {
		return err
	}

	resp, err := a.Conn.Request("user.get", data, time.Second)
	if err != nil {
		return err
	}

	json.Unmarshal(resp.Data, &ur)
	if err != nil {
		return err
	}

	msg := fmt.Sprintf(`{"username": "%s", "type": "%s", "admin": %t}`, c.Username, userType, admin)
	_, err = a.Conn.Request("user.set", []byte(msg), time.Second)
	if err != nil {
		return err
	}

	return nil
}

// getUser fetches the specified user from user-store
func (a *Authenticator) getUser(username string) (*User, error) {
	var u User

	resp, err := a.Conn.Request("user.get", []byte(`{"username": "`+username+`"}`), time.Second)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(resp.Data, &u)
	if err != nil {
		return nil, err
	}

	if u.ID == 0 {
		return nil, ErrUnauthorized
	}
	return &u, nil
}

// localAuth handles local provider authentication
func (a *Authenticator) localAuth(c Credentials) (*jwt.Token, error) {
	u, err := a.getUser(c.Username)
	if err != nil {
		return nil, err
	}

	ok, err := u.valid(c)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, ErrUnauthorized
	}

	token := generateToken(u.Username, a.Expiry)
	token.Claims.(jwt.MapClaims)["admin"] = u.Admin

	return token, nil
}

// verifyMFA checks if a verification code is valid
func (a *Authenticator) verifyMFA(c Credentials) error {
	resp, err := a.Conn.Request("mfa.auth", []byte(`{"username": "`+c.Username+`", "verification_code": "`+c.VerificationCode+`"}`), time.Second)
	if err != nil {
		return err
	}

	var result mfaResponse
	err = json.Unmarshal(resp.Data, &result)
	if err != nil {
		return err
	}

	if !result.OK {
		return ErrUnauthorized
	}

	return nil
}
