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

### in turms of variables

#### tcp_estats_global_table
- [ ] TCP_ESTATS_GLOBAL_TABLE_LIMSTATE,
- [ ] TCP_ESTATS_GLOBAL_TABLE_LIMSTATE_TS,
- [x] TCP_ESTATS_GLOBAL_TABLE_START_TS,
- [x] TCP_ESTATS_GLOBAL_TABLE_CURRENT_TS,
- [x] TCP_ESTATS_GLOBAL_TABLE_START_TV

#### tcp_estats_connection_table
- [x] TCP_ESTATS_CONNECTION_TABLE_ADDRESS_TYPE,
- [x] TCP_ESTATS_CONNECTION_TABLE_LOCAL_ADDRESS,
- [x] TCP_ESTATS_CONNECTION_TABLE_REMOTE_ADDRESS,
- [x] TCP_ESTATS_CONNECTION_TABLE_LOCAL_PORT,
- [x] TCP_ESTATS_CONNECTION_TABLE_REMOTE_PORT

#### tcp_estats_perf_table
- [ ] TCP_ESTATS_PERF_TABLE_SEGSOUT,
- [ ] TCP_ESTATS_PERF_TABLE_DATASEGSOUT,
- [ ] TCP_ESTATS_PERF_TABLE_DATAOCTETSOUT,  // u64
- [ ] TCP_ESTATS_PERF_TABLE_SEGSRETRANS,
- [ ] TCP_ESTATS_PERF_TABLE_OCTETSRETRANS,
- [ ] TCP_ESTATS_PERF_TABLE_SEGSIN,
- [ ] TCP_ESTATS_PERF_TABLE_DATASEGSIN,
- [ ] TCP_ESTATS_PERF_TABLE_DATAOCTETSIN,
- [ ] TCP_ESTATS_PERF_TABLE_NORMALRTTM,
- [ ] TCP_ESTATS_PERF_TABLE_HIGHRTTM,
- [ ] /*		ElapsedSecs */
- [ ] /*		ElapsedMicroSecs */
- [ ] /*		StartTimeStamp */
- [ ] /*		CurMSS */
- [ ] /*		PipeSize */
- [ ] TCP_ESTATS_PERF_TABLE_MAXPIPESIZE,
- [ ] /*		SmoothedRTT */
- [ ] /*		CurRTO */
- [ ] TCP_ESTATS_PERF_TABLE_CONGSIGNALS,
- [ ] /*		CurCwnd */
- [ ] /*		CurSsthresh */
- [ ] TCP_ESTATS_PERF_TABLE_TIMEOUTS,
- [ ] /*		CurRwinSent */
- [ ] TCP_ESTATS_PERF_TABLE_MAXRWINSENT,
- [ ] TCP_ESTATS_PERF_TABLE_ZERORWINSENT,
- [ ] /*		CurRwinRcvd */
- [ ] TCP_ESTATS_PERF_TABLE_MAXRWINRCVD,
- [ ] TCP_ESTATS_PERF_TABLE_ZERORWINRCVD,
- [ ] /*		SndLimTransRwin */
- [ ] /*		SndLimTransCwnd */
- [ ] /*		SndLimTransSnd */
- [ ] /*		SndLimTimeRwin */
- [ ] /*		SndLimTimeCwnd */
- [ ] /*		SndLimTimeSnd */
- [ ] // TODO: figure out how to do this
- [ ] // u32		snd_lim_trans[TCP_ESTATS_SNDLIM_NSTATES];
- [ ] // u32		snd_lim_time[TCP_ESTATS_SNDLIM_NSTATES];

#### tcp_estats_path_table
- [ ] TCP_ESTATS_PATH_TABLE_NONRECOVDAEPISODES,
- [ ] TCP_ESTATS_PATH_TABLE_SUMOCTETSREORDERED,
- [ ] TCP_ESTATS_PATH_TABLE_NONRECOVDA,
- [ ] TCP_ESTATS_PATH_TABLE_SAMPLERTT,
- [ ] TCP_ESTATS_PATH_TABLE_MAXRTT,
- [ ] TCP_ESTATS_PATH_TABLE_MINRTT,
- [ ] TCP_ESTATS_PATH_TABLE_SUMRTT,
- [ ] TCP_ESTATS_PATH_TABLE_COUNTRTT,
- [ ] TCP_ESTATS_PATH_TABLE_MAXRTO,
- [ ] TCP_ESTATS_PATH_TABLE_MINRTO,
- [ ] TCP_ESTATS_PATH_TABLE_IPTTL,    // u8
- [ ] TCP_ESTATS_PATH_TABLE_IPTOSIN,  // u8
- [ ] TCP_ESTATS_PATH_TABLE_PRECONGSUMCWND,
- [ ] TCP_ESTATS_PATH_TABLE_PRECONGSUMRTT,
- [ ] TCP_ESTATS_PATH_TABLE_POSTCONGSUMRTT,
- [ ] TCP_ESTATS_PATH_TABLE_POSTCONGCOUNTRTT,
- [ ] TCP_ESTATS_PATH_TABLE_ECNSIGNALS,
- [ ] TCP_ESTATS_PATH_TABLE_DUPACKEPISODES,
- [ ] TCP_ESTATS_PATH_TABLE_DUPACKSOUT,
- [ ] TCP_ESTATS_PATH_TABLE_CERCVD,
- [ ] TCP_ESTATS_PATH_TABLE_ECESENT

#### tcp_estats_stack_table
- [ ] TCP_ESTATS_STACK_TABLE_ACTIVEOPEN,
- [ ] TCP_ESTATS_STACK_TABLE_MAXSSCWND,
- [ ] TCP_ESTATS_STACK_TABLE_MAXCACWND,
- [ ] TCP_ESTATS_STACK_TABLE_MAXSSTHRESH,
- [ ] TCP_ESTATS_STACK_TABLE_MINSSTHRESH,
- [ ] TCP_ESTATS_STACK_TABLE_DUPACKSIN,
- [ ] TCP_ESTATS_STACK_TABLE_SPURIOUSFRDETECTED,
- [ ] TCP_ESTATS_STACK_TABLE_SPURIOUSRTODETECTED,
- [ ] TCP_ESTATS_STACK_TABLE_SOFTERRORS,
- [ ] TCP_ESTATS_STACK_TABLE_SOFTERRORREASON,
- [ ] TCP_ESTATS_STACK_TABLE_SLOWSTART,
- [ ] TCP_ESTATS_STACK_TABLE_CONGAVOID,
- [ ] TCP_ESTATS_STACK_TABLE_OTHERREDUCTIONS,
- [ ] TCP_ESTATS_STACK_TABLE_CONGOVERCOUNT,
- [ ] TCP_ESTATS_STACK_TABLE_FASTRETRAN,
- [ ] TCP_ESTATS_STACK_TABLE_SUBSEQUENTTIMEOUTS,
- [ ] TCP_ESTATS_STACK_TABLE_ABRUPTTIMEOUTS,
- [ ] TCP_ESTATS_STACK_TABLE_SACKSRCVD,
- [ ] TCP_ESTATS_STACK_TABLE_SACKBLOCKSRCVD,
- [ ] TCP_ESTATS_STACK_TABLE_SENDSTALL,
- [ ] TCP_ESTATS_STACK_TABLE_DSACKDUPS,
- [ ] TCP_ESTATS_STACK_TABLE_MAXMSS,
- [ ] TCP_ESTATS_STACK_TABLE_MINMSS,
- [ ] TCP_ESTATS_STACK_TABLE_SNDINITIAL,
- [ ] TCP_ESTATS_STACK_TABLE_RECINITIAL,
- [ ] TCP_ESTATS_STACK_TABLE_CURRETXQUEUE,
- [ ] TCP_ESTATS_STACK_TABLE_MAXRETXQUEUE,
- [ ] TCP_ESTATS_STACK_TABLE_MAXREASMQUEUE,
- [ ] TCP_ESTATS_STACK_TABLE_EARLYRETRANS,
- [ ] TCP_ESTATS_STACK_TABLE_EARLYRETRANSDELAY

#### tcp_estats_app_table
- [ ] TCP_ESTATS_APP_TABLE_SNDMAX,
- [ ] TCP_ESTATS_APP_TABLE_THRUOCTETSACKED,
- [ ] TCP_ESTATS_APP_TABLE_THRUOCTETSRECEIVED,
- [ ] TCP_ESTATS_APP_TABLE_MAXAPPWQUEUE,
- [ ] TCP_ESTATS_APP_TABLE_MAXAPPRQUEUE

#### tcp_estats_extras_table
- [ ] TCP_ESTATS_EXTRAS_TABLE_OTHERREDUCTIONSCV,
- [ ] TCP_ESTATS_EXTRAS_TABLE_OTHERREDUCTIONSCM,
- [ ] TCP_ESTATS_EXTRAS_TABLE_PRIORITY

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
