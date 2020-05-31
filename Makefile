main:
	go build -o dkimkeygen cmd/dkimkeygen/main.go
	go build -o dkimsign cmd/dkimsign/main.go
	go build -o dkimverify cmd/dkimverify/main.go

.PHONY: main
