deps:
	@go get -u github.com/golang/dep/cmd/dep
	@dep ensure

dev-deps: deps
	@go get github.com/alecthomas/gometalinter
	@gometalinter --install

lint:
	@gometalinter --config .linter.conf

test:
	@go test -v -cover ./pkg/authenticator
