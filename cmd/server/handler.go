/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"encoding/json"

	"github.com/ernestio/authenticator/pkg/authenticator"
	"github.com/nats-io/nats"
)

// authenticationGetHandler handles all authentication requests for
// authentication.get
func authenticationGetHandler(msg *nats.Msg) {
	var c authenticator.Credentials

	err := json.Unmarshal(msg.Data, &c)
	if err != nil {
		nc.Publish(msg.Reply, []byte(`{"ok": false, "message": "`+err.Error()+`"}`))
		return
	}

	res, err := auth.Authenticate(c)
	if err != nil {
		nc.Publish(msg.Reply, []byte(`{"ok": false, "message": "`+err.Error()+`"}`))
		return
	}

	token, err := json.Marshal(res)
	if err != nil {
		nc.Publish(msg.Reply, []byte(`{"ok": false, "message": "`+err.Error()+`"}`))
		return
	}

	nc.Publish(msg.Reply, []byte(token))
}
