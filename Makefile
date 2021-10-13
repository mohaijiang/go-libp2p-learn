all: build-linux build-windows build-mac

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o p2pssh-linux-amd64

build-windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o p2pssh-windows-amd64

build-mac:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o p2pssh-darwin-amd64