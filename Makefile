.PHONY: build fmt vet tidy clean

build:
	CGO_ENABLED=0 go build -o bptools .

fmt:
	gofmt -w .

vet:
	go vet ./...

tidy:
	go mod tidy

clean:
	rm -f bptools bptools-*
