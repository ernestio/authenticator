deps:
	@go get -u github.com/golang/dep/cmd/dep
	@dep ensure

test:
	@go test -v -cover ./pkg/authenticator
