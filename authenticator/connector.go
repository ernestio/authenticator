/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package authenticator

import (
	"time"

	"github.com/nats-io/nats"
)

type Connector interface {
	Request(subj string, data []byte, timeout time.Duration) (*nats.Msg, error)
}
