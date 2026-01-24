.PHONY: run build

run:
	go run cmd/api/main.go

build:
	go build -o bin/api.exe cmd/api/main.go
