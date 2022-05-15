//go:generate go run golang.org/x/tools/cmd/stringer -type=Operation
//go:generate go run golang.org/x/tools/cmd/stringer -type=GlobalVar
//go:generate go run golang.org/x/tools/cmd/stringer -type=ConnectionVar
//go:generate go run golang.org/x/tools/cmd/stringer -type=PathVar
//go:generate go run golang.org/x/tools/cmd/stringer -type=PerfVar
//go:generate go run golang.org/x/tools/cmd/stringer -type=StackVar
//go:generate go run golang.org/x/tools/cmd/stringer -type=AppVar
//go:generate go run golang.org/x/tools/cmd/stringer -type=ExtrasVar

package tcp_estats

import (
	"flag"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"sync"

	"tcp_estats-ebpf/endian"
)

var (
	verbose = flag.Bool("verbose", false, "extra logging if set to true")
)

type Operation uint32

const (
	OPERATION_SET Operation = iota
	OPERATION_ADD
	OPERATION_SUB
	OPERATION_MAX
	OPERATION_MIN
)

type GlobalVar uint32

const (
	GLOBAL_TABLE_LIMSTATE GlobalVar = iota
	GLOBAL_TABLE_LIMSTATE_TS
	GLOBAL_TABLE_START_TS
	GLOBAL_TABLE_CURRENT_TS
	GLOBAL_TABLE_START_TV
)

type ConnectionVar uint32

const (
	CONNECTION_TABLE_ADDRESS_TYPE ConnectionVar = iota
	CONNECTION_TABLE_LOCAL_ADDRESS
	CONNECTION_TABLE_REMOTE_ADDRESS
	CONNECTION_TABLE_LOCAL_PORT
	CONNECTION_TABLE_REMOTE_PORT
)

type PerfVar uint32

const (
	PERF_TABLE_SEGSOUT PerfVar = iota
	PERF_TABLE_DATASEGSOUT
	PERF_TABLE_DATAOCTETSOUT // u64
	PERF_TABLE_SEGSRETRANS
	PERF_TABLE_OCTETSRETRANS
	PERF_TABLE_SEGSIN
	PERF_TABLE_DATASEGSIN
	PERF_TABLE_DATAOCTETSIN // u64
	PERF_TABLE_NORMALRTTM
	PERF_TABLE_HIGHRTTM
	/*		ElapsedSecs */
	/*		ElapsedMicroSecs */
	/*		StartTimeStamp */
	/*		CurMSS */
	/*		PipeSize */
	PERF_TABLE_MAXPIPESIZE
	/*		SmoothedRTT */
	/*		CurRTO */
	PERF_TABLE_CONGSIGNALS
	/*		CurCwnd */
	/*		CurSsthresh */
	PERF_TABLE_TIMEOUTS
	/*		CurRwinSent */
	PERF_TABLE_MAXRWINSENT
	PERF_TABLE_ZERORWINSENT
	/*		CurRwinRcvd */
	PERF_TABLE_MAXRWINRCVD
	PERF_TABLE_ZERORWINRCVD
	/*		SndLimTransRwin */
	/*		SndLimTransCwnd */
	/*		SndLimTransSnd */
	/*		SndLimTimeRwin */
	/*		SndLimTimeCwnd */
	/*		SndLimTimeSnd */
	// TODO: figure this out
	//u32		snd_lim_trans[TCP_ESTATS_SNDLIM_NSTATES];
	//u32		snd_lim_time[TCP_ESTATS_SNDLIM_NSTATES];

)

type PathVar uint32

const (
	PATH_TABLE_NONRECOVDAEPISODES PathVar = iota
	PATH_TABLE_SUMOCTETSREORDERED
	PATH_TABLE_NONRECOVDA
	PATH_TABLE_SAMPLERTT
	PATH_TABLE_MAXRTT
	PATH_TABLE_MINRTT
	PATH_TABLE_SUMRTT
	PATH_TABLE_COUNTRTT
	PATH_TABLE_MAXRTO
	PATH_TABLE_MINRTO
	PATH_TABLE_PTTL
	PATH_TABLE_PTOSIN
	PATH_TABLE_PRECONGSUMCWND
	PATH_TABLE_PRECONGSUMRTT
	PATH_TABLE_POSTCONGSUMRTT
	PATH_TABLE_POSTCONGCOUNTRTT
	PATH_TABLE_ECNSIGNALS
	PATH_TABLE_DUPACKEPISODES
	PATH_TABLE_DUPACKSOUT
	PATH_TABLE_CERCVD
	PATH_TABLE_ECESENT
)

type StackVar uint32

const (
	STACK_TABLE_ACTIVEOPEN StackVar = iota
	STACK_TABLE_MAXSSCWND
	STACK_TABLE_MAXCACWND
	STACK_TABLE_MAXSSTHRESH
	STACK_TABLE_MINSSTHRESH
	STACK_TABLE_DUPACKSIN
	STACK_TABLE_SPURIOUSFRDETECTED
	STACK_TABLE_SPURIOUSRTODETECTED
	STACK_TABLE_SOFTERRORS
	STACK_TABLE_SOFTERRORREASON
	STACK_TABLE_SLOWSTART
	STACK_TABLE_CONGAVOID
	STACK_TABLE_OTHERREDUCTIONS
	STACK_TABLE_CONGOVERCOUNT
	STACK_TABLE_FASTRETRAN
	STACK_TABLE_SUBSEQUENTTIMEOUTS
	STACK_TABLE_ABRUPTTIMEOUTS
	STACK_TABLE_SACKSRCVD
	STACK_TABLE_SACKBLOCKSRCVD
	STACK_TABLE_SENDSTALL
	STACK_TABLE_DSACKDUPS
	STACK_TABLE_MAXMSS
	STACK_TABLE_MINMSS
	STACK_TABLE_SNDINITIAL
	STACK_TABLE_RECINITIAL
	STACK_TABLE_CURRETXQUEUE
	STACK_TABLE_MAXRETXQUEUE
	STACK_TABLE_MAXREASMQUEUE
	STACK_TABLE_EARLYRETRANS
	STACK_TABLE_EARLYRETRANSDELAY
)

type AppVar uint32

const (
	APP_TABLE_SNDMAX AppVar = iota
	APP_TABLE_THRUOCTETSACKED
	APP_TABLE_THRUOCTETSRECEIVED
	APP_TABLE_MAXAPPWQUEUE
	APP_TABLE_MAXAPPRQUEUE
)

type ExtrasVar uint32

const (
	EXTRAS_TABLE_OTHERREDUCTIONSCV ExtrasVar = iota
	EXTRAS_TABLE_OTHERREDUCTIONSCM
	EXTRAS_TABLE_PRIORITY
)

type SndLimState int

const (
	SNDLIM_NONE SndLimState = iota - 1
	SNDLIM_SENDER
	SNDLIM_CWND
	SNDLIM_RWIN
	SNDLIM_STARTUP
	SNDLIM_TSODEFER
	SNDLIM_PACE
)

type Vars interface {
	GlobalVar | ConnectionVar | PerfVar | PathVar |
		StackVar | AppVar | ExtrasVar
}

type Table[V Vars] struct {
	sync.RWMutex
	// TODO: this may need to be more general or a union-like type.
	M map[V]uint32
}

func tableString[V Vars](t Table[V]) string {
	t.RLock()
	defer t.RUnlock()

	var keykeys []string
	keys := make(map[string]V)

	keyLen := 0
	for k, _ := range t.M {
		keyStr := fmt.Sprint(k)
		keykeys = append(keykeys, keyStr)
		keys[keyStr] = k
		keyLen = max(len(keyStr), keyLen)
	}

	s := fmt.Sprintf("+%s+%s+\n", strings.Repeat("-", keyLen+2), strings.Repeat("-", 10))

	rowFormatStr := fmt.Sprintf("| %%%ds | %%%dd |\n", keyLen, 8)

	sort.Strings(keykeys)
	for _, k := range keykeys {
		v := keys[k]
		s += fmt.Sprintf(rowFormatStr, v, t.M[v])
	}

	s += fmt.Sprintf("+%s+%s+", strings.Repeat("-", keyLen+2), strings.Repeat("-", 10))

	return s
}

type tables struct {
	global     Table[GlobalVar]
	connection Table[ConnectionVar]
	perf       Table[PerfVar]
	path       Table[PathVar]
	stack      Table[StackVar]
	app        Table[AppVar]
	extras     Table[ExtrasVar]
}

type Estats struct {
	tables tables
}

func New() *Estats {
	e := new(Estats)
	e.tables.global = Table[GlobalVar]{M: make(map[GlobalVar]uint32)}
	e.tables.connection = Table[ConnectionVar]{M: make(map[ConnectionVar]uint32)}
	e.tables.perf = Table[PerfVar]{M: make(map[PerfVar]uint32)}
	e.tables.path = Table[PathVar]{M: make(map[PathVar]uint32)}
	e.tables.stack = Table[StackVar]{M: make(map[StackVar]uint32)}
	e.tables.app = Table[AppVar]{M: make(map[AppVar]uint32)}
	e.tables.extras = Table[ExtrasVar]{M: make(map[ExtrasVar]uint32)}
	return e
}

func (e Estats) String() string {
	s := "..- global -..\n"
	s += tableString(e.tables.global) + "\n"
	s += "..- connection -..\n"
	s += tableString(e.tables.connection) + "\n"
	s += "..- perf -..\n"
	s += tableString(e.tables.perf) + "\n"
	s += "..- path -..\n"
	s += tableString(e.tables.path) + "\n"
	s += "..- stack -..\n"
	s += tableString(e.tables.stack) + "\n"
	s += "..- app -..\n"
	s += tableString(e.tables.app) + "\n"
	s += "..- extras -..\n"
	s += tableString(e.tables.extras) + "\n"

	return s
}

func (e *Estats) GetTableForVar(v any) any {
	switch v.(type) {
	case GlobalVar:
		return &e.tables.global
	case ConnectionVar:
		return &e.tables.connection
	case PerfVar:
		return &e.tables.perf
	case PathVar:
		return &e.tables.path
	case StackVar:
		return &e.tables.stack
	case AppVar:
		return &e.tables.app
	case ExtrasVar:
		return &e.tables.extras
	default:
		log.Fatalf("unknown table for var %s", v)
		return nil
	}
}

func max[T int | uint32](x, y T) T {
	if x < y {
		return y
	}
	return x
}

func min[T int | uint32](x, y T) T {
	if x > y {
		return y
	}
	return x
}

// You may wonder why this isn't declared as a method on Estats.
// Generics don't work on methods, only functions.
func DoOp[V Vars](e *Estats, rec Record) {
	v := V(rec.Var)

	t := e.GetTableForVar(v).(*Table[V])
	t.RLock()
	defer t.RUnlock()

	if *verbose {
		log.Printf("DoOp: %s\n", rec)
	}
	switch rec.Op {
	case OPERATION_SET:
		if *verbose {
			log.Printf(" . setting %s to %d\n", v, rec.Val)
		}
		t.M[v] = rec.Val
	case OPERATION_ADD:
		if *verbose {
			log.Printf(" . adding %s to %d\n", v, rec.Val)
		}
		t.M[v] += rec.Val
	case OPERATION_SUB:
		if *verbose {
			log.Printf(" . subtracting %d from %s\n", rec.Val, v)
		}
		t.M[v] -= rec.Val
	case OPERATION_MAX:
		if *verbose {
			log.Printf(" . setting %s to max of %d and %d\n", v, t.M[v], v)
		}
		t.M[v] = max(t.M[v], rec.Val)
	case OPERATION_MIN:
		if *verbose {
			log.Printf(" . setting %s to min of %d and %d\n", v, t.M[v], v)
		}
		t.M[v] = min(t.M[v], rec.Val)
	}
}

// Mirror of `retord` in tcp_estats.h
type Record struct {
	PidTgid uint64
	Saddr   uint32
	Daddr   uint32
	Sport   uint16
	Dport   uint16
	Op      Operation
	Var     uint32
	Val     uint32
}

func (rec Record) String() string {
	return fmt.Sprintf("[P: %d, S: %s:%d, D: %s:%d]: %s on %d with %d", rec.PidTgid, intToIP(rec.Saddr), rec.Sport, intToIP(rec.Daddr), rec.Dport, rec.Op, rec.Var, rec.Val)
}

func intToIP(num uint32) net.IP {
	ip := make(net.IP, 4)
	endian.Native.PutUint32(ip, num)
	return ip
}
