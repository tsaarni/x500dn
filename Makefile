all: test lint

test:
	go test -v ./...

lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.1.2 run

update-modules:
	go get -u -t ./... && go mod tidy
