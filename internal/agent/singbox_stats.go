package agent

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
)

// sing-box 的 v2ray_api 服务名与 xray 不同（真源 init 里覆盖为 v2ray.core.app.stats.command），
// xray CLI 查不了，这里自带最小 gRPC 客户端：请求编码为零字节空消息（空 patterns 返回全部
// 计数器），响应按 stats.proto 手工解 wire（Stat{name=1, value=2}），不引 protobuf codegen。
const singboxStatsMethod = "/v2ray.core.app.stats.command.StatsService/QueryStats"

type rawCodec struct{}

func (rawCodec) Name() string { return "proto" }

func (rawCodec) Marshal(v any) ([]byte, error) {
	switch m := v.(type) {
	case []byte:
		return m, nil
	case *[]byte:
		return *m, nil
	default:
		return nil, fmt.Errorf("raw codec: unsupported type %T", v)
	}
}

func (rawCodec) Unmarshal(data []byte, v any) error {
	switch m := v.(type) {
	case *[]byte:
		*m = data
		return nil
	default:
		return fmt.Errorf("raw codec: unsupported type %T", v)
	}
}

func init() {
	encoding.RegisterCodec(rawCodec{})
}

func collectSingboxStats(ctx context.Context, api string) (map[string]int64, error) {
	call, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := grpc.NewClient(api, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("sing-box api: %w", err)
	}
	defer conn.Close()
	var raw []byte
	if err := conn.Invoke(call, singboxStatsMethod, []byte{}, &raw); err != nil {
		return nil, fmt.Errorf("sing-box query stats: %w", err)
	}
	return decodeQueryStats(raw)
}

func decodeQueryStats(data []byte) (map[string]int64, error) {
	counters := map[string]int64{}
	rest := data
	for len(rest) > 0 {
		field, wire, n, err := consumeTag(rest)
		if err != nil {
			return nil, err
		}
		rest = rest[n:]
		payload, n, err := consumePayload(rest, wire)
		if err != nil {
			return nil, err
		}
		rest = rest[n:]
		if field != 1 || wire != 2 {
			continue
		}
		name, value, err := decodeStat(payload)
		if err != nil {
			return nil, err
		}
		if name != "" && value > 0 {
			counters[name] = value
		}
	}
	return counters, nil
}

func consumeTag(data []byte) (field, wire uint64, n int, err error) {
	tag, n := binary.Uvarint(data)
	if n <= 0 {
		return 0, 0, 0, errors.New("proto tag")
	}
	return tag >> 3, tag & 7, n, nil
}

func consumePayload(data []byte, wire uint64) ([]byte, int, error) {
	switch wire {
	case 0:
		_, n := binary.Uvarint(data)
		if n <= 0 {
			return nil, 0, errors.New("proto varint")
		}
		return nil, n, nil
	case 1:
		if len(data) < 8 {
			return nil, 0, errors.New("proto fixed64")
		}
		return nil, 8, nil
	case 2:
		size, n := binary.Uvarint(data)
		if n <= 0 || size > uint64(len(data)-n) {
			return nil, 0, errors.New("proto bytes")
		}
		return data[n : n+int(size)], n + int(size), nil
	case 5:
		if len(data) < 4 {
			return nil, 0, errors.New("proto fixed32")
		}
		return nil, 4, nil
	default:
		return nil, 0, errors.New("proto wire type")
	}
}

func decodeStat(data []byte) (string, int64, error) {
	var name string
	var value int64
	rest := data
	for len(rest) > 0 {
		field, wire, n, err := consumeTag(rest)
		if err != nil {
			return "", 0, err
		}
		rest = rest[n:]
		switch {
		case field == 1 && wire == 2:
			payload, n, err := consumePayload(rest, wire)
			if err != nil {
				return "", 0, err
			}
			name = string(payload)
			rest = rest[n:]
		case field == 2 && wire == 0:
			raw, n := binary.Uvarint(rest)
			if n <= 0 {
				return "", 0, errors.New("proto varint")
			}
			value = int64(raw)
			rest = rest[n:]
		default:
			_, n, err := consumePayload(rest, wire)
			if err != nil {
				return "", 0, err
			}
			rest = rest[n:]
		}
	}
	return name, value, nil
}
