FROM golang:1.8.2-alpine

RUN apk add --update git && apk add --update make && rm -rf /var/cache/apk/*

ADD . /go/src/github.com/${GITHUB_ORG:-ernestio}/authenticator
WORKDIR /go/src/github.com/${GITHUB_ORG:-ernestio}/authenticator

RUN make deps && cd cmd/authenticator && go install

ENTRYPOINT ./authenticator
