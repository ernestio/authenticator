/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package authenticator

import (
	"encoding/json"
	"errors"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

const DEFAULTEXPIRY = time.Hour * 24

var ErrUnauthorized = errors.New("Authentication failed")

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type authResponse struct {
	OK    bool   `json:"ok"`
	Token string `json:"token"`
}

type userResponse struct {
	Code string `json:"_code"`
}

type Authenticator struct {
	Conn      Connector
	Providers []string
	Secret    string
	Expiry    time.Duration
}

func New(providers []string, secret string) *Authenticator {
	return &Authenticator{
		Providers: providers,
		Secret:    secret,
		Expiry:    DEFAULTEXPIRY,
	}
}

func (a *Authenticator) Authenticate(c Credentials) (*authResponse, error) {
	var err error
	var token *jwt.Token
	var userType string

	for _, provider := range a.Providers {
		token, err = a.auth(provider, c)
		if err == nil {
			userType = provider
			break
		}
	}

	if err != nil {
		return nil, ErrUnauthorized
	}

	// create user if one doesn't exist
	if userType != "local" {
		err = a.createUser(c, userType)
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

func (a *Authenticator) createUser(c Credentials, userType string) error {
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

	if ur.Code == "404" {
		_, err = a.Conn.Request("user.set", []byte(`{"username": "`+c.Username+`", "type": "`+userType+`"}`), time.Second)
		if err != nil {
			return err
		}
	}

	return nil
}

func (a *Authenticator) auth(provider string, c Credentials) (*jwt.Token, error) {
	var ar authResponse

	if !a.validProvider(provider) {
		return nil, errors.New("Unknown provider type")
	}

	if provider == "local" {
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

	resp, err := a.Conn.Request(provider+".auth", data, time.Second)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(resp.Data, &ar)
	if err != nil {
		return nil, err
	}

	if ar.OK {
		return generateToken(a.Expiry, c.Username), nil
	}

	return nil, ErrUnauthorized
}

func (a *Authenticator) validProvider(provider string) bool {
	for _, p := range a.Providers {
		if p == provider {
			return true
		}
	}
	return false
}

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

func (a *Authenticator) localAuth(c Credentials) (*jwt.Token, error) {
	u, err := a.getUser(c.Username)
	if err != nil {
		return nil, err
	}

	if !u.valid(c) {
		return nil, ErrUnauthorized
	}

	token := generateToken(a.Expiry, u.Username)
	token.Claims.(jwt.MapClaims)["admin"] = u.Admin

	return token, nil
}
