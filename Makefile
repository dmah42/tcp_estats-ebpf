OUTPUT=tcp_estats_ebpf

.PHONY: build
build: gen $(OUTPUT)

.PHONY: gen
gen: tcp_estats.c tcp_estats.h tcp_estats/tcp_estats.go
	go generate main.go
	go generate tcp_estats/tcp_estats.go

.PHONY: sum
sum: go.sum

.PHONY: fmt
fmt: sum
	go fmt *.go

.PHONY: clean
clean:
	-@rm $(OUTPUT)
	-@rm tcpestats_bpfe*.go
	-@rm tcpestats_bpfe*.o

.PHONY: run
run: build
	sudo ./$(OUTPUT)

$(OUTPUT): tcpestats_bpfel.go tcpestats_bpfeb.go main.go endian/endian.go tcp_estats/*.go
	CGO_ENABLED=1 go build -o $@

tcpestats_bpfe%.go: tcp_estats.c tcp_estats.h
	go generate main.go
	-@rm tcpestats_bpfe*.o

go.sum:
	go mod download github.com/cilium/ebpf
	go get github.com/ciliun/ebpf/cmd/bpf2go
