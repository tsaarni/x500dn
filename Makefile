all: check

test:
	go test -v ./...

check: test
	golangci-lint run
	gosec -quiet ./...

install-tools:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.50.1
	go install github.com/securego/gosec/v2/cmd/gosec@v2.14.0

update-modules:
	go get -u -t ./... && go mod tidy
