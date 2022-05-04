//go:generate go run golang.org/x/tools/cmd/stringer -type=Operation
//go:generate go run golang.org/x/tools/cmd/stringer -type=GlobalVar
//go:generate go run golang.org/x/tools/cmd/stringer -type=ConnectionVar
//go:generate go run golang.org/x/tools/cmd/stringer -type=PathVar
//go:generate go run golang.org/x/tools/cmd/stringer -type=PerfVar
//go:generate go run golang.org/x/tools/cmd/stringer -type=StackVar
//go:generate go run golang.org/x/tools/cmd/stringer -type=AppVar
//go:generate go run golang.org/x/tools/cmd/stringer -type=ExtrasVar

package tcp_estats

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

/*
// No methods for now..
type Table interface{}

type GlobalTable struct {
	Users int

	Limstate   SndLimState
	LimstateTS uint64

	StartTS   uint64
	CurrentTS uint64

	StartTv time.Time
}

type ConnectionTable struct {
	AddressType uint32

	LocalAddress  Address
	RemoteAddress Address

	LocalPort uint16
	RemPort   uint16
}

type PerfTable struct {
	SegsOut uint32
	// TODO: more
}

type PathTable struct {
	NonRecovDAEpisodes uint32
	SumOctetsReordered uint32
	NonRecovDA         uint32
	SampleRTT          uint32
	MaxRTT             uint32
	MinRTT             uint32
	SumRTT             uint64
	CountRTT           uint32
	MaxRTO             uint32
	MinRTO             uint32
	IpTtl              uint8
	IpTosIn            uint8
	PreCongSumCwnd     uint32
	PreCongSumRTT      uint32
	PostCongSumRTT     uint32
	PostCongCountRTT   uint32
	ECNsignals         uint32
	DupAckEpisodes     uint32
	DupAcksOut         uint32
	CERcvd             uint32
	ECESent            uint32
}
type StackTable struct {
	ActiveOpen          uint32
	MaxSsCwnd           uint32
	MaxCaCwnd           uint32
	MaxSsthresh         uint32
	MinSsthresh         uint32
	DupAcksIn           uint32
	SpuriousFrDetected  uint32
	SpuriousRtoDetected uint32
	SoftErrors          uint32
	SoftErrorReason     uint32
	SlowStart           uint32
	CongAvoid           uint32
	OtherReductions     uint32
	CongOverCount       uint32
	FastRetran          uint32
	SubsequentTimeouts  uint32
	AbruptTimeouts      uint32
	SACKsRcvd           uint32
	SACKBlocksRcvd      uint32
	SendStall           uint32
	DSACKDups           uint32
	MaxMSS              uint32
	MinMSS              uint32
	SndInitial          uint32
	RecInitial          uint32
	CurRetxQueue        uint32
	MaxRetxQueue        uint32
	MaxReasmQueue       uint32
	EarlyRetrans        uint32
	EarlyRetransDelay   uint32
}

type AppTable struct {
	SndMax          uint32
	ThruOctetsAcked uint64
	// TODO: more
}

type ExtrasTable struct {
	OtherReductionsCV uint32
	OtherReductionsCM uint32
	Priority          uint32
}
*/

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

type Tables struct {
	GlobalTable     map[GlobalVar]uint32
	ConnectionTable map[ConnectionVar]uint32
	PerfTable       map[PerfVar]uint32
	PathTable       map[PathVar]uint32
	StackTable      map[StackVar]uint32
	AppTable        map[AppVar]uint32
	ExtrasTable     map[ExtrasVar]uint32
}

type Estats struct {
	Tables Tables
}

func New() *Estats {
	e := new(Estats)
	e.Tables.GlobalTable = make(map[GlobalVar]uint32)
	e.Tables.ConnectionTable = make(map[ConnectionVar]uint32)
	e.Tables.PerfTable = make(map[PerfVar]uint32)
	e.Tables.PathTable = make(map[PathVar]uint32)
	e.Tables.StackTable = make(map[StackVar]uint32)
	e.Tables.AppTable = make(map[AppVar]uint32)
	e.Tables.ExtrasTable = make(map[ExtrasVar]uint32)
	return e
}

// Mirror of `entry` in tcp_estats.c
type Key struct {
	Saddr uint32
	Daddr uint32
	Sport uint16
	Dport uint16
}

type Entry struct {
	Key Key
	Op  Operation
	Var uint32
	Val uint32
}
