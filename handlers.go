package main

import (
	"encoding/json"

	"github.com/ernestio/authenticator/authenticator"
	"github.com/nats-io/nats"
)

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

	t, err := json.Marshal(res)
	if err != nil {
		nc.Publish(msg.Reply, []byte(`{"ok": false, "message": "`+err.Error()+`"}`))
		return
	}

	nc.Publish(msg.Reply, []byte(t))
}
