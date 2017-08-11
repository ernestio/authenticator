/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package authenticator

import (
	"crypto/subtle"
	"encoding/base64"

	"golang.org/x/crypto/scrypt"
)

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
	Type     string `json:"type"`
	Salt     string `json:"salt"`
	Admin    bool   `json:"admin"`
}

const HashSize = 64

func (u *User) valid(c Credentials) bool {
	if c.Username == u.Username {
		pw, err := base64.StdEncoding.DecodeString(u.Password)
		if err != nil {
			return false
		}

		salt, err := base64.StdEncoding.DecodeString(u.Salt)
		if err != nil {
			return false
		}

		hash, err := scrypt.Key([]byte(c.Password), salt, 16384, 8, 1, HashSize)
		if err != nil {
			return false
		}

		// Compare in constant time to mitigate timing attacks
		if subtle.ConstantTimeCompare(pw, hash) == 1 {
			return true
		}

		return false
	}

	return false
}
