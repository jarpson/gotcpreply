
tidy:
	GO111MODULE=on GOPROXY=direct GOSUMDB=off go mod tidy

build:
	go build -o gotcpreply

linux:
	env GO111MODULE=on CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o gotcpreply_linux   *.go
