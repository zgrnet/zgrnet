package relay

import (
	"github.com/vibing/zgrnet/pkg/noise"
)

// Strategy represents a relay routing strategy preference.
type Strategy byte

const (
	// StrategyAuto lets the relay node decide (default).
	StrategyAuto Strategy = 0
	// StrategyFastest prefers the lowest latency path.
	StrategyFastest Strategy = 1
	// StrategyCheapest prefers the lowest cost path.
	StrategyCheapest Strategy = 2
)

// Router provides next-hop routing decisions for relay forwarding.
// The implementation is responsible for knowing the network topology.
// Currently a simple static map; Host will provide a dynamic implementation.
type Router interface {
	// NextHop returns the next peer to forward to for reaching dst.
	// If nextHop == dst, the destination is directly reachable (send RELAY_2).
	// If nextHop != dst, forward via intermediate relay (send RELAY_1).
	NextHop(dst [32]byte, strategy Strategy) (nextHop [32]byte, err error)
}

// Action represents a relay forwarding action to be executed by the caller.
// The relay engine produces Actions; the caller (UDP/Host) sends them.
type Action struct {
	Dst      [32]byte // Next-hop peer to send to
	Protocol byte     // Protocol byte (ProtocolRelay1, ProtocolRelay2, ProtocolPong)
	Data     []byte   // Encoded message body
}

// NodeMetrics contains local node metrics for PONG responses.
type NodeMetrics struct {
	Load       byte   // 0-255 (0=idle, 255=full)
	RelayCount uint16 // Active relay connections
	BwAvail    uint16 // Available bandwidth KB/s
	Price      uint32 // Price per MB in token smallest unit, 0=free
}

// HandleRelay0 processes a RELAY_0 (first-hop) message.
// from is the sender's public key (implicit from the Noise session).
// data is the message body after the protocol byte has been stripped.
// Returns an Action to forward the packet, or an error.
func HandleRelay0(router Router, from [32]byte, data []byte) (*Action, error) {
	r0, err := DecodeRelay0(data)
	if err != nil {
		return nil, err
	}

	if r0.TTL == 0 {
		return nil, ErrTTLExpired
	}

	nextHop, err := router.NextHop(r0.DstKey, r0.Strategy)
	if err != nil {
		return nil, err
	}

	if nextHop == r0.DstKey {
		// Direct: send RELAY_2 to destination
		r2 := &Relay2{
			SrcKey:  from,
			Payload: r0.Payload,
		}
		return &Action{
			Dst:      nextHop,
			Protocol: noise.ProtocolRelay2,
			Data:     EncodeRelay2(r2),
		}, nil
	}

	// Forward: send RELAY_1 to next hop
	r1 := &Relay1{
		TTL:      r0.TTL - 1,
		Strategy: r0.Strategy,
		SrcKey:   from,
		DstKey:   r0.DstKey,
		Payload:  r0.Payload,
	}
	return &Action{
		Dst:      nextHop,
		Protocol: noise.ProtocolRelay1,
		Data:     EncodeRelay1(r1),
	}, nil
}

// HandleRelay1 processes a RELAY_1 (middle-hop) message.
// data is the message body after the protocol byte has been stripped.
// Returns an Action to forward the packet, or an error.
func HandleRelay1(router Router, data []byte) (*Action, error) {
	r1, err := DecodeRelay1(data)
	if err != nil {
		return nil, err
	}

	if r1.TTL == 0 {
		return nil, ErrTTLExpired
	}

	nextHop, err := router.NextHop(r1.DstKey, r1.Strategy)
	if err != nil {
		return nil, err
	}

	if nextHop == r1.DstKey {
		// Direct: send RELAY_2 to destination
		r2 := &Relay2{
			SrcKey:  r1.SrcKey,
			Payload: r1.Payload,
		}
		return &Action{
			Dst:      nextHop,
			Protocol: noise.ProtocolRelay2,
			Data:     EncodeRelay2(r2),
		}, nil
	}

	// Forward: send RELAY_1 to next hop (TTL-1)
	fwd := &Relay1{
		TTL:      r1.TTL - 1,
		Strategy: r1.Strategy,
		SrcKey:   r1.SrcKey,
		DstKey:   r1.DstKey,
		Payload:  r1.Payload,
	}
	return &Action{
		Dst:      nextHop,
		Protocol: noise.ProtocolRelay1,
		Data:     EncodeRelay1(fwd),
	}, nil
}

// HandleRelay2 processes a RELAY_2 (last-hop) message.
// data is the message body after the protocol byte has been stripped.
// Returns the source public key and the inner payload (a complete Type 4
// transport message encrypted under the A-B session).
// The caller should feed the payload back through the decrypt pipeline.
func HandleRelay2(data []byte) (src [32]byte, payload []byte, err error) {
	r2, err := DecodeRelay2(data)
	if err != nil {
		return [32]byte{}, nil, err
	}
	return r2.SrcKey, r2.Payload, nil
}

// HandlePing processes a PING (protocol 70) message and returns a PONG action.
// from is the sender's public key. data is the message body after protocol byte.
// metrics provides local node info for the PONG response.
func HandlePing(from [32]byte, data []byte, metrics NodeMetrics) (*Action, error) {
	ping, err := DecodePing(data)
	if err != nil {
		return nil, err
	}

	pong := &Pong{
		PingID:     ping.PingID,
		Timestamp:  ping.Timestamp, // Echo back for RTT calculation
		Load:       metrics.Load,
		RelayCount: metrics.RelayCount,
		BwAvail:    metrics.BwAvail,
		Price:      metrics.Price,
	}

	return &Action{
		Dst:      from,
		Protocol: noise.ProtocolPong,
		Data:     EncodePong(pong),
	}, nil
}
