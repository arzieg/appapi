test:
	go test -v ./...
	
lint:
	@golangci-lint run


.PHONY: all lint test
