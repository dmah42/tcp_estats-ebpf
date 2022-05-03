package tcp_estats

import (
	"time"
)

type Operation int

const (
	OPERATION_SET Operation = iota
	OPERATION_ADD           = iota
	OPERATION_SUB           = iota
	OPERATION_INC           = iota
	OPERATION_DEC           = iota
)

type GlobalVar int

const (
	GLOBAL_TABLE_LIMSTATE    GlobalVar = iota
	GLOBAL_TABLE_LIMSTATE_TS           = iota
	GLOBAL_TABLE_START_TS              = iota
	GLOBAL_TABLE_CURRENT_TS            = iota
	GLOBAL_TABLE_START_TV              = iota
)

type ConnectionVar int

const (
	CONNECTION_TABLE_ADDRESS_TYPE   ConnectionVar = iota
	CONNECTION_TABLE_LOCAL_ADDRESS                = iota
	CONNECTION_TABLE_REMOTE_ADDRESS               = iota
	CONNECTION_TABLE_LOCAL_PORT                   = iota
	CONNECTION_TABLE_REMOTE_PORT                  = iota
)

type PerfVar int

const (
	PERF_TABLE_SEGSOUT PerfVar = iota
	// TODO: more perf
)

type PathVar int

const (
	PATH_TABLE_NONRECOVDAEPISODES PathVar = iota
	PATH_TABLE_SUMOCTETSREORDERED         = iota
	PATH_TABLE_NONRECOVDA                 = iota
	PATH_TABLE_SAMPLERTT                  = iota
	PATH_TABLE_MAXRTT                     = iota
	PATH_TABLE_MINRTT                     = iota
	PATH_TABLE_SUMRTT                     = iota
	PATH_TABLE_COUNTRTT                   = iota
	PATH_TABLE_MAXRTO                     = iota
	PATH_TABLE_MINRTO                     = iota
	PATH_TABLE_PTTL                       = iota
	PATH_TABLE_PTOSIN                     = iota
	PATH_TABLE_PRECONGSUMCWND             = iota
	PATH_TABLE_PRECONGSUMRTT              = iota
	PATH_TABLE_POSTCONGSUMRTT             = iota
	PATH_TABLE_POSTCONGCOUNTRTT           = iota
	PATH_TABLE_ECNSIGNALS                 = iota
	PATH_TABLE_DUPACKEPISODES             = iota
	PATH_TABLE_DUPACKSOUT                 = iota
	PATH_TABLE_CERCVD                     = iota
	PATH_TABLE_ECESENT                    = iota
)

type StackVar int

const (
	STACK_TABLE_ACTIVEOPEN          StackVar = iota
	STACK_TABLE_MAXSSCWND                    = iota
	STACK_TABLE_MAXCACWND                    = iota
	STACK_TABLE_MAXSSTHRESH                  = iota
	STACK_TABLE_MINSSTHRESH                  = iota
	STACK_TABLE_DUPACKSIN                    = iota
	STACK_TABLE_SPURIOUSFRDETECTED           = iota
	STACK_TABLE_SPURIOUSRTODETECTED          = iota
	STACK_TABLE_SOFTERRORS                   = iota
	STACK_TABLE_SOFTERRORREASON              = iota
	STACK_TABLE_SLOWSTART                    = iota
	STACK_TABLE_CONGAVOID                    = iota
	STACK_TABLE_OTHERREDUCTIONS              = iota
	STACK_TABLE_CONGOVERCOUNT                = iota
	STACK_TABLE_FASTRETRAN                   = iota
	STACK_TABLE_SUBSEQUENTTIMEOUTS           = iota
	STACK_TABLE_ABRUPTTIMEOUTS               = iota
	STACK_TABLE_SACKSRCVD                    = iota
	STACK_TABLE_SACKBLOCKSRCVD               = iota
	STACK_TABLE_SENDSTALL                    = iota
	STACK_TABLE_DSACKDUPS                    = iota
	STACK_TABLE_MAXMSS                       = iota
	STACK_TABLE_MINMSS                       = iota
	STACK_TABLE_SNDINITIAL                   = iota
	STACK_TABLE_RECINITIAL                   = iota
	STACK_TABLE_CURRETXQUEUE                 = iota
	STACK_TABLE_MAXRETXQUEUE                 = iota
	STACK_TABLE_MAXREASMQUEUE                = iota
	STACK_TABLE_EARLYRETRANS                 = iota
	STACK_TABLE_EARLYRETRANSDELAY            = iota
)

type AppVar int

const (
	APP_TABLE_SNDMAX          AppVar = iota
	APP_TABLE_THRUOCTETSACKED        = iota
	// TODO: more
)

type ExtrasVar int

const (
	EXTRAS_TABLE_OTHERREDUCTIONSCV ExtrasVar = iota
	EXTRAS_TABLE_OTHERREDUCTIONSCM           = iota
	EXTRAS_TABLE_PRIORITY                    = iota
)

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
