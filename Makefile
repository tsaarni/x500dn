all: test lint

test:
	go test -v ./...

lint:
	go run github.com/golangci/golangci-lint/cmd/golangci-lint@v1.61.0 run

update-modules:
	go get -u -t ./... && go mod tidy
