OUTPUT=tcpinfo_ebpf

.PHONY: build
build: clean gen $(OUTPUT)

.PHONY: gen
gen: tcpinfo_bpfel.go tcpinfo_bpfeb.go
	go generate main.go

.PHONY: sum
sum: go.sum

.PHONY: fmt
fmt: sum
	go fmt *.go

.PHONY: clean
clean:
	-@rm $(OUTPUT)
	-@rm tcpinfo_bpfe*.go
	-@rm tcpinfo_bpfe*.o

$(OUTPUT): tcpinfo_bpfel.go tcpinfo_bpfeb.go main.go endian/endian.go
	CGO_ENABLED=1 go build -o $<

tcpinfo_bpfe%.go: tcpinfo.c
	go generate main.go

go.sum:
	go mod download github.com/cilium/ebpf
	go get github.com/ciliun/ebpf/cmd/bpf2go
