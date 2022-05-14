OUTPUT=tcp_estats_ebpf

.PHONY: build
build: gen $(OUTPUT)

.PHONY: gen
gen: probe/*.c probe/*.h tcp_estats/tcp_estats.go
	go generate main.go
	go generate tcp_estats/tcp_estats.go

.PHONY: sum
sum: go.sum

.PHONY: fmt
fmt: *.go tcp_estats/*.go probe/*.c probe/*.h
	go fmt *.go
	go fmt tcp_estats/*.go
	clang-format -i --style=Google probe/*.c
	clang-format -i --style=Google probe/*.h

# TODO: probe tests?
.PHONY: test
test: *.go tcp_estats/*.go
	go test tcp_estats/*.go

.PHONY: clean
clean:
	-@rm $(OUTPUT)
	-@rm tcpestats_bpfe*.go
	-@rm tcpestats_bpfe*.o

.PHONY: run
run: build test
	sudo ./$(OUTPUT)

$(OUTPUT): tcpestats_bpfel.go tcpestats_bpfeb.go main.go endian/endian.go tcp_estats/*.go
	CGO_ENABLED=1 go build -o $@

tcpestats_bpfe%.go: probe/*.c probe/*.h
	go generate main.go
#	-@rm tcpestats_bpfe*.o

go.sum:
	go mod download github.com/cilium/ebpf
	go get github.com/ciliun/ebpf/cmd/bpf2go
