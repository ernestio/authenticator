package main

import (
	"encoding/json"

	"github.com/ernestio/authenticator/authenticator"
	"github.com/nats-io/nats"
)

func handler(msg *nats.Msg) {
	var c authenticator.Credentials

	err := json.Unmarshal(msg.Data, &c)
	if err != nil {
		nc.Publish(msg.Reply, []byte(`failed to decode NATS message`))
	}

	token := auth.Authenticate(c)

	t, err := json.Marshal(token)
	if err != nil {
		nc.Publish(msg.Reply, []byte(`failed to encode token response`))
	}

	nc.Publish(msg.Reply, []byte(t))
}
