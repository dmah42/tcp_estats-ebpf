OUTPUT=bin/tcp_estats

.PHONY: build
build: $(OUTPUT)

.PHONY: sum
sum: go.sum

.PHONY: fmt
fmt: cmd/tcp_estats/*.go internal/tcp_estats/*.go probe/*.c probe/*.h
	go fmt cmd/tcp_estats/*.go
	go fmt internal/tcp_estats/*.go
	clang-format -i --style=Google probe/*.c
	clang-format -i --style=Google probe/*.h

# TODO: probe tests?
.PHONY: test
test: cmd/tcp_estats/*.go  internal/tcp_estats/*.go
	go test ./internal/tcp_estats
	go test ./cmd/tcp_estats

.PHONY: clean
clean:
	-@rm $(OUTPUT)
	-@rm internal/tcp_estats/tcp_estats_bpfe*.go
	-@rm internal/tcp_estats/tcp_estats_bpfe*.o
	-@rm internal/tcp_estats/*_string.go

.PHONY: run
run: build test
	sudo ./$(OUTPUT)

$(OUTPUT): internal/tcp_estats/tcp_estats_bpfel.go internal/tcp_estats/tcp_estats_bpfeb.go internal/tcp_estats/*.go cmd/tcp_estats/*.go 
	CGO_ENABLED=1 go build -o $@ ./cmd/tcp_estats

internal/tcp_estats/tcp_estats_bpfe%.go: probe/*.c probe/*.h
	go generate ./internal/tcp_estats/tcp_estats.go

internal/tcp_estats/*_string.go: internal/tcp_estats/tcp_estats.go
	go generate ./internal/tcp_estats/tcp_estats.go

go.sum:
	go mod download github.com/cilium/ebpf
	go get github.com/ciliun/ebpf/cmd/bpf2go
