Attempts to integrate [RFC4898](https://datatracker.ietf.org/doc/html/rfc4898)
in the upstream Linux kernel failed due to the large overhead.  Even though it
could be controlled through sysctl and was completely removable, it was felt
to be too much code.

Also, TCPINFO already existed as a centralized method for tracing TCP internals
which was extensible and integrated with existing tools like `ss`.

Now we have [eBPF](https://ebpf.io) I thought it would be fun to try to
replicate the functionality of estats without the intrusive code necessary to
do so in kernel space.

## original patches
https://gitlab.cs.washington.edu/syslab/linux-3.16.0-tcp-estats contains the
source for an estats-patched 3.16.0 kernel.  The most relevant parts are:

* [net/tcp.h](https://gitlab.cs.washington.edu/syslab/linux-3.16.0-tcp-estats/-/blob/master/include/net/tcp.h)
* [net/tcp_estats.h](https://gitlab.cs.washington.edu/syslab/linux-3.16.0-tcp-estats/-/blob/master/include/net/tcp_estats.h)
* [net/tcp_estats_mib_var.h](https://gitlab.cs.washington.edu/syslab/linux-3.16.0-tcp-estats/-/blob/master/include/net/tcp_estats_mib_var.h)
* [net/ipv4/tcp_estats.c](https://gitlab.cs.washington.edu/syslab/linux-3.16.0-tcp-estats/-/blob/master/net/ipv4/tcp_estats.c)

## approach

### BPF (C)
Created a ring buffer per estats table and a "global" one (which isn't entirely
in line with the RFC but allows things to be more generic). Each entry contains:
* a key to identify the socket: PID_TGID:saddr:sport:daddr:dport
    * no ipv6 support yet but sooon
* an enum value representing the variable
* an enum value representing the op (set, add, inc, dec)
* the operand value (unset for inc and dec)

Care needs to be taken to ensure the variable matches the ringbuffer so the right
variable goes to the right table.

### Go
A single goroutine that reads from a ringbuffer and populates the tables. All the
tables are maps guarded with rwmutexes (because we smart) and there's a higher
level rwmutex protecting the tables themselves, created the first time we encounter
a key we haven't seen before.

Go 1.18+ is necessary as the project requires generics to do some type-agnostic stuff
and enable the single read loop.

## current status
program runs successfully, but the tcp estats will need validation against a "real"
version at some point.

all values are defined and ready, but only the following hooks have been implemented:

* `tcp_create_openreq_child` (exit)
* `tcp_init_sock` (exit)
* `tcp_v4_do_rcv` (entry and exit)

## next steps

* more implementation of stats collection, requiring more program hooks.
* tests? :D
* validation of results

## appendix

### old approaches

#### ring buffer per table
Create a ring buffer per estats table, and one more for stats creation. Each
entry in the ring buffer would contain:

* a key to uniquely identify the socket: PID:sip:sport:dip:dport
* an enum value representing the variable to operate on
* an enum value representing the operation (set, add.. maybe inc, dec)
* the operand value

One goroutine to read each ring buffer, populating the tables. Error checking
would ensure the variable is present in the given table. There may be a way
to generalise the goroutines by passing in a table identifier as the operations
are fixed from that point.

We may need a way to wait on the creation ringbuffer when filling in stats, just
in case there's a race condition between the go routines and we get a stats
operation on a socket which we don't know about yet.

#### all the logic in C
The approach I'll take is to replicate the estats structs in the eBPF layer, and
hook in either through kprobes or existing function calls to populate the estats
appropriately.

This approach didn't really work as it requires a lot of logic in the eBPF layer
including allocation to do it well, and I think there's a better approach...
