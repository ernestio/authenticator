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

var Secret string
var ErrUnauthorized = errors.New("Authentication failed")

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AuthResponse struct {
	OK bool `json:"ok"`
}

type UserResponse struct {
	Code string `json:"_code"`
}

type Authenticator struct {
	Conn      Connector
	Providers []string
}

func New(providers []string) *Authenticator {
	return &Authenticator{
		Providers: providers,
	}
}

func (a *Authenticator) Authenticate(c Credentials) (string, error) {
	var err error
	var token string
	var userType string

	for _, provider := range a.Providers {
		token, err = a.auth(provider, c)
		if err == nil {
			userType = provider
			break
		}
	}

	if err != nil {
		return "", ErrUnauthorized
	}

	// create user if one doesn't exist
	if userType != "local" {
		err = a.createUser(userType, c)
		if err != nil {
			return "", err
		}
	}

	// token gen here?

	return token, err
}

func (a *Authenticator) createUser(userType string, c Credentials) error {
	var ur UserResponse

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
		_, err := a.Conn.Request("user.set", data, time.Second)
		if err != nil {
			return err
		}
	}

	return nil
}

func (a *Authenticator) auth(provider string, c Credentials) (string, error) {
	var ar AuthResponse

	if !a.validProvider(provider) {
		return "", errors.New("Unknown provider type")
	}

	if provider == "local" {
		token, err := a.localAuth(c)
		if err != nil {
			return "", err
		}
		return token, nil
	}

	data, err := json.Marshal(c)
	if err != nil {
		return "", err
	}

	resp, err := a.Conn.Request(provider+".auth", data, time.Second)
	if err != nil {
		return "", err
	}

	err = json.Unmarshal(resp.Data, &ar)
	if err != nil {
		return "", err
	}

	if ar.OK {
		// return token and nil err
		return "", nil
	}

	return "", ErrUnauthorized
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

func (a *Authenticator) localAuth(c Credentials) (string, error) {
	u, err := a.getUser(c.Username)
	if err != nil {
		return "", err
	}
	if u.valid(c) {
		token := jwt.New(jwt.SigningMethodHS256)
		claims := token.Claims.(jwt.MapClaims)
		claims["username"] = u.Username
		claims["admin"] = u.Admin
		claims["exp"] = time.Now().Add(time.Hour * 24).Unix()
		tokenString, err := token.SignedString([]byte(Secret))
		if err != nil {
			return "", err
		}

		return tokenString, nil
	}
	return "", ErrUnauthorized
}
