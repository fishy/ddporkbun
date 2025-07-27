.phony: build
build: main.go
	GODEBUG=netdns=go+1 go build -trimpath

.phony: install
install: main.go
	GODEBUG=netdns=go+1 go install -trimpath
