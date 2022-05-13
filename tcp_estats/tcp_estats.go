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
	"fmt"
	"log"
	"net"
	"strings"
	"sync"

	"tcp_estats-ebpf/endian"
)

type Operation uint32

const (
	OPERATION_SET Operation = iota
	OPERATION_ADD Operation = iota
	OPERATION_SUB Operation = iota
	OPERATION_MAX Operation = iota
	OPERATION_MIN Operation = iota
)

type GlobalVar uint32

const (
	GLOBAL_TABLE_LIMSTATE    GlobalVar = iota
	GLOBAL_TABLE_LIMSTATE_TS GlobalVar = iota
	GLOBAL_TABLE_START_TS    GlobalVar = iota
	GLOBAL_TABLE_CURRENT_TS  GlobalVar = iota
	GLOBAL_TABLE_START_TV    GlobalVar = iota
)

type ConnectionVar uint32

const (
	CONNECTION_TABLE_ADDRESS_TYPE   ConnectionVar = iota
	CONNECTION_TABLE_LOCAL_ADDRESS  ConnectionVar = iota
	CONNECTION_TABLE_REMOTE_ADDRESS ConnectionVar = iota
	CONNECTION_TABLE_LOCAL_PORT     ConnectionVar = iota
	CONNECTION_TABLE_REMOTE_PORT    ConnectionVar = iota
)

type PerfVar uint32

const (
	PERF_TABLE_SEGSOUT       PerfVar = iota
	PERF_TABLE_DATASEGSOUT   PerfVar = iota
	PERF_TABLE_DATAOCTETSOUT PerfVar = iota //u64
	PERF_TABLE_SEGSRETRANS   PerfVar = iota
	PERF_TABLE_OCTETSRETRANS PerfVar = iota
	PERF_TABLE_SEGSIN        PerfVar = iota
	PERF_TABLE_DATASEGSIN    PerfVar = iota
	PERF_TABLE_DATAOCTETSIN  PerfVar = iota //u64
	PERF_TABLE_NORMALRTTM    PerfVar = iota
	PERF_TABLE_HIGHRTTM      PerfVar = iota
	/*		ElapsedSecs */
	/*		ElapsedMicroSecs */
	/*		StartTimeStamp */
	/*		CurMSS */
	/*		PipeSize */
	PERF_TABLE_MAXPIPESIZE PerfVar = iota
	/*		SmoothedRTT */
	/*		CurRTO */
	PERF_TABLE_CONGSIGNALS PerfVar = iota
	/*		CurCwnd */
	/*		CurSsthresh */
	PERF_TABLE_TIMEOUTS PerfVar = iota
	/*		CurRwinSent */
	PERF_TABLE_MAXRWINSENT  PerfVar = iota
	PERF_TABLE_ZERORWINSENT PerfVar = iota
	/*		CurRwinRcvd */
	PERF_TABLE_MAXRWINRCVD  PerfVar = iota
	PERF_TABLE_ZERORWINRCVD PerfVar = iota
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
	PATH_TABLE_SUMOCTETSREORDERED PathVar = iota
	PATH_TABLE_NONRECOVDA         PathVar = iota
	PATH_TABLE_SAMPLERTT          PathVar = iota
	PATH_TABLE_MAXRTT             PathVar = iota
	PATH_TABLE_MINRTT             PathVar = iota
	PATH_TABLE_SUMRTT             PathVar = iota
	PATH_TABLE_COUNTRTT           PathVar = iota
	PATH_TABLE_MAXRTO             PathVar = iota
	PATH_TABLE_MINRTO             PathVar = iota
	PATH_TABLE_PTTL               PathVar = iota
	PATH_TABLE_PTOSIN             PathVar = iota
	PATH_TABLE_PRECONGSUMCWND     PathVar = iota
	PATH_TABLE_PRECONGSUMRTT      PathVar = iota
	PATH_TABLE_POSTCONGSUMRTT     PathVar = iota
	PATH_TABLE_POSTCONGCOUNTRTT   PathVar = iota
	PATH_TABLE_ECNSIGNALS         PathVar = iota
	PATH_TABLE_DUPACKEPISODES     PathVar = iota
	PATH_TABLE_DUPACKSOUT         PathVar = iota
	PATH_TABLE_CERCVD             PathVar = iota
	PATH_TABLE_ECESENT            PathVar = iota
)

type StackVar uint32

const (
	STACK_TABLE_ACTIVEOPEN          StackVar = iota
	STACK_TABLE_MAXSSCWND           StackVar = iota
	STACK_TABLE_MAXCACWND           StackVar = iota
	STACK_TABLE_MAXSSTHRESH         StackVar = iota
	STACK_TABLE_MINSSTHRESH         StackVar = iota
	STACK_TABLE_DUPACKSIN           StackVar = iota
	STACK_TABLE_SPURIOUSFRDETECTED  StackVar = iota
	STACK_TABLE_SPURIOUSRTODETECTED StackVar = iota
	STACK_TABLE_SOFTERRORS          StackVar = iota
	STACK_TABLE_SOFTERRORREASON     StackVar = iota
	STACK_TABLE_SLOWSTART           StackVar = iota
	STACK_TABLE_CONGAVOID           StackVar = iota
	STACK_TABLE_OTHERREDUCTIONS     StackVar = iota
	STACK_TABLE_CONGOVERCOUNT       StackVar = iota
	STACK_TABLE_FASTRETRAN          StackVar = iota
	STACK_TABLE_SUBSEQUENTTIMEOUTS  StackVar = iota
	STACK_TABLE_ABRUPTTIMEOUTS      StackVar = iota
	STACK_TABLE_SACKSRCVD           StackVar = iota
	STACK_TABLE_SACKBLOCKSRCVD      StackVar = iota
	STACK_TABLE_SENDSTALL           StackVar = iota
	STACK_TABLE_DSACKDUPS           StackVar = iota
	STACK_TABLE_MAXMSS              StackVar = iota
	STACK_TABLE_MINMSS              StackVar = iota
	STACK_TABLE_SNDINITIAL          StackVar = iota
	STACK_TABLE_RECINITIAL          StackVar = iota
	STACK_TABLE_CURRETXQUEUE        StackVar = iota
	STACK_TABLE_MAXRETXQUEUE        StackVar = iota
	STACK_TABLE_MAXREASMQUEUE       StackVar = iota
	STACK_TABLE_EARLYRETRANS        StackVar = iota
	STACK_TABLE_EARLYRETRANSDELAY   StackVar = iota
)

type AppVar uint32

const (
	APP_TABLE_SNDMAX             AppVar = iota
	APP_TABLE_THRUOCTETSACKED    AppVar = iota // u64
	APP_TABLE_THRUOCTETSRECEIVED AppVar = iota // u64
	APP_TABLE_MAXAPPWQUEUE       AppVar = iota
	APP_TABLE_MAXAPPRQUEUE       AppVar = iota
)

type ExtrasVar uint32

const (
	EXTRAS_TABLE_OTHERREDUCTIONSCV ExtrasVar = iota
	EXTRAS_TABLE_OTHERREDUCTIONSCM ExtrasVar = iota
	EXTRAS_TABLE_PRIORITY          ExtrasVar = iota
)

type SndLimState int

const (
	SNDLIM_NONE     SndLimState = -1
	SNDLIM_SENDER               = iota
	SNDLIM_CWND                 = iota
	SNDLIM_RWIN                 = iota
	SNDLIM_STARTUP              = iota
	SNDLIM_TSODEFER             = iota
	SNDLIM_PACE                 = iota
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

	keyLen := 0
	for k, _ := range t.M {
		keyLen = max(len(string(k)), keyLen)
	}

	s := fmt.Sprintf("+%s+%s+\n", strings.Repeat("-", keyLen + 2), strings.Repeat("-", 8))

	rowFormatStr := fmt.Sprintf("| %%%d%%s | %%%d%%d |\n", keyLen, 8)
	for k, v := range t.M {
		s += fmt.Sprintf(rowFormatStr, k, v)
	}

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

func max[T int|uint32](x, y T) T {
	if x < y {
		return y
	}
	return x
}

func min[T int|uint32](x, y T) T {
	if x > y {
		return y
	}
	return x
}

// You may wonder why this isn't declared as a method on Estats.
// Generics don't work on methods, only functions.
func DoOp[V Vars](e *Estats, entry Entry) {
	v := V(entry.Var)

	t := e.GetTableForVar(v).(*Table[V])
	t.RLock()
	defer t.RUnlock()

	switch entry.Op {
	case OPERATION_SET:
		//log.Printf(" . setting %v to %d", v, entry.Val)
		t.M[v] = entry.Val
	case OPERATION_ADD:
		//log.Printf(" . adding %v to %d", v, entry.Val)
		t.M[v] += entry.Val
	case OPERATION_SUB:
		//log.Printf(" . subtracting %d from %v", entry.Val, v)
		t.M[v] -= entry.Val
	case OPERATION_MAX:
		//log.Printf(" . setting max to %v", v)
		t.M[v] = max(t.M[v], entry.Val)
	case OPERATION_MIN:
		//log.Printf(" . setting min to %v", v)
		t.M[v] = min(t.M[v], entry.Val)
	}
}

// Mirror of `entry` in tcp_estats.c
type Key struct {
	PidTgid uint64
	Saddr   uint32
	Daddr   uint32
	Sport   uint16
	Dport   uint16
}

type Entry struct {
	Key Key
	Op  Operation
	Var uint32
	Val uint32
}

func (k Key) String() string {
	return fmt.Sprintf("[P: %d, S: %s:%d, D: %s:%d]", k.PidTgid, intToIP(k.Saddr), k.Sport, intToIP(k.Daddr), k.Dport)
}

func intToIP(num uint32) net.IP {
	ip := make(net.IP, 4)
	endian.Native.PutUint32(ip, num)
	return ip
}

