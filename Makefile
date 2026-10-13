.PHONY: test vet fmt integration

test:
	go test ./...

vet:
	go vet ./...

fmt:
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)

integration:
	go test ./exepatch/ -run TestIntegration -v
