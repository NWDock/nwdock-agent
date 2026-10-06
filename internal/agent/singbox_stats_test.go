package agent

import (
	"context"
	"encoding/binary"
	"net"
	"reflect"
	"testing"

	"google.golang.org/grpc"
)

func pbVarint(v uint64) []byte {
	var buf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(buf[:], v)
	return buf[:n]
}

func pbBytes(field uint64, data []byte) []byte {
	out := pbVarint(field<<3 | 2)
	out = append(out, pbVarint(uint64(len(data)))...)
	return append(out, data...)
}

func pbStat(name string, value uint64) []byte {
	out := pbBytes(1, []byte(name))
	out = append(out, pbVarint(2<<3|0)...)
	return append(out, pbVarint(value)...)
}

func TestDecodeQueryStats(t *testing.T) {
	response := pbBytes(1, pbStat("user>>>sub-1>>>traffic>>>uplink", 300))
	response = append(response, pbBytes(1, pbStat("inbound>>>nw-abcd1234-20000>>>traffic>>>downlink", 7))...)
	response = append(response, pbBytes(1, pbStat("zeroed", 0))...)
	response = append(response, pbVarint(3<<3|0)...)
	response = append(response, pbVarint(99)...)
	counters, err := decodeQueryStats(response)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int64{
		"user>>>sub-1>>>traffic>>>uplink":                  300,
		"inbound>>>nw-abcd1234-20000>>>traffic>>>downlink": 7,
	}
	if !reflect.DeepEqual(counters, want) {
		t.Fatalf("counters: got %v want %v", counters, want)
	}
}

func TestDecodeQueryStatsRejectsGarbage(t *testing.T) {
	for _, data := range [][]byte{{0x07}, {0x0A}, {0x0A, 0x05, 'a'}, {0xFF}} {
		if _, err := decodeQueryStats(data); err == nil {
			t.Fatalf("expected error for % x", data)
		}
	}
}

func TestCollectSingboxStats(t *testing.T) {
	response := pbBytes(1, pbStat("user>>>sub-1>>>traffic>>>uplink", 300))
	response = append(response, pbBytes(1, pbStat("inbound>>>nw-abcd1234-20000>>>traffic>>>uplink", 42))...)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: "v2ray.core.app.stats.command.StatsService",
		Methods: []grpc.MethodDesc{{
			MethodName: "QueryStats",
			Handler: func(any, context.Context, func(any) error, grpc.UnaryServerInterceptor) (any, error) {
				return response, nil
			},
		}},
	}, nil)
	go server.Serve(lis)
	defer server.Stop()

	counters, err := collectSingboxStats(context.Background(), lis.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int64{
		"user>>>sub-1>>>traffic>>>uplink":                300,
		"inbound>>>nw-abcd1234-20000>>>traffic>>>uplink": 42,
	}
	if !reflect.DeepEqual(counters, want) {
		t.Fatalf("counters: got %v want %v", counters, want)
	}
}

func TestCollectSingboxStatsUnavailable(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := lis.Addr().String()
	_ = lis.Close()
	if _, err := collectSingboxStats(context.Background(), addr); err == nil {
		t.Fatal("expected error for dead endpoint")
	}
}
