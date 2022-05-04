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
	"log"
	"sync"
)

type Operation uint32

const (
	OPERATION_SET Operation = iota
	OPERATION_ADD Operation = iota
	OPERATION_SUB Operation = iota
	OPERATION_INC Operation = iota
	OPERATION_DEC Operation = iota
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
	PERF_TABLE_SEGSOUT PerfVar = iota
	// TODO: more perf
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
	APP_TABLE_SNDMAX          AppVar = iota
	APP_TABLE_THRUOCTETSACKED AppVar = iota
	// TODO: more
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
	M map[V]uint32
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
