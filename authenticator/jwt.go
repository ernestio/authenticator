/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package authenticator

import (
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

// generateToken generates a JWT token
func generateToken(username string, exp time.Duration) *jwt.Token {
	if exp == 0 {
		exp = time.Hour * 24
	} else {
		exp = time.Hour * exp
	}

	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)
	claims["username"] = username
	claims["exp"] = time.Now().Add(exp).Unix()

	return token
}
