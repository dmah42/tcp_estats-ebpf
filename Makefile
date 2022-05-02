OUTPUT=tcp_estats_ebpf

.PHONY: build
build: clean gen $(OUTPUT)

.PHONY: gen
gen: tcp_estats_bpfel.go tcp_estats_bpfeb.go
	go generate main.go

.PHONY: sum
sum: go.sum

.PHONY: fmt
fmt: sum
	go fmt *.go

.PHONY: clean
clean:
	-@rm $(OUTPUT)
	-@rm tcp_estats_bpfe*.go
	-@rm tcp_estats_bpfe*.o

.PHONY: run
run: build
	sudo ./$(OUTPUT)

$(OUTPUT): tcp_estats_bpfel.go tcp_estats_bpfeb.go main.go endian/endian.go
	CGO_ENABLED=1 go build -o $@

tcp_estats_bpfe%.go: tcp_estats.c
	go generate main.go
	-@rm tcp_estats_bpfe*.o

go.sum:
	go mod download github.com/cilium/ebpf
	go get github.com/ciliun/ebpf/cmd/bpf2go
