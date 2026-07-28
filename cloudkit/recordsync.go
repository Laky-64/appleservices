package cloudkit

import (
	"fmt"
	"time"

	"github.com/Laky-64/http"
	"github.com/Laky-64/http/types"

	"github.com/Laky-64/appleservices/internal/protobuf"
	"github.com/Laky-64/appleservices/internal/uuid"
	"github.com/Laky-64/appleservices/octagon"
)

func buildRecordSyncBody(zone, userID string, header, token []byte) []byte {
	op := protobuf.NewWriter()
	op.WriteBytes(1, []byte(uuid.New()))
	op.WriteVarint(2, 213)
	op.WriteVarint(4, 1)

	zn := protobuf.NewWriter()
	zn.WriteBytes(1, []byte(zone))
	zn.WriteVarint(2, 6)

	ow := protobuf.NewWriter()
	ow.WriteBytes(1, []byte(userID))
	ow.WriteVarint(2, 7)

	zid := protobuf.NewWriter()
	zid.WriteBytes(1, zn.Bytes())
	zid.WriteBytes(2, ow.Bytes())
	zid.WriteVarint(3, 1)

	zfr := protobuf.NewWriter()
	if token != nil {
		zfr.WriteBytes(1, token)
	}
	zfr.WriteBytes(2, zid.Bytes())
	zfr.WriteVarint(5, 3)

	reqOp := protobuf.NewWriter()
	if header != nil {
		reqOp.WriteBytes(1, header)
	}
	reqOp.WriteBytes(2, op.Bytes())
	reqOp.WriteBytes(213, zfr.Bytes())
	return reqOp.Bytes()
}

const (
	SyncInconsistent     = 1
	SyncConsistent       = 2
	SyncNoPendingChanges = 3
)

func SyncContinuationToken(body []byte) []byte {
	if inner := changesResponse(body); inner != nil {
		for _, in := range inner {
			if in.Number == 2 && in.WireType == protobuf.WireBytes {
				return in.Bytes
			}
		}
	}
	return nil
}

func SyncStatus(body []byte) int {
	if inner := changesResponse(body); inner != nil {
		for _, in := range inner {
			if in.Number == 4 && in.WireType == protobuf.WireVarint {
				return int(in.Varint)
			}
		}
	}
	return 0
}

func changesResponse(body []byte) []protobuf.Field {
	msg := body
	if m, err := octagon.UnframeCodeInvoke(body); err == nil {
		msg = m
	}
	fields, err := protobuf.ReadFields(msg)
	if err != nil {
		return nil
	}
	for _, f := range fields {
		if f.Number == 213 && f.WireType == protobuf.WireBytes {
			inner, err := protobuf.ReadFields(f.Bytes)
			if err != nil {
				return nil
			}
			return inner
		}
	}
	return nil
}

func (c *Client) RecordSyncZone(zone string) ([]byte, error) {
	return c.RecordSyncZoneSince(zone, nil)
}

func (c *Client) RecordSyncZoneSince(zone string, token []byte) ([]byte, error) {
	result, err := c.recordSyncZoneOnce(zone, token)
	if result != nil && result.StatusCode == statusUnauthorized && c.reauthenticate() {
		result, err = c.recordSyncZoneOnce(zone, token)
	}
	if result != nil && result.StatusCode != 200 {
		return nil, fmt.Errorf("cloudkit: record/sync %s status %d: %s", zone, result.StatusCode, snippet(result.Body))
	}
	if err != nil {
		return nil, fmt.Errorf("cloudkit: record/sync %s: %w", zone, err)
	}
	if result == nil {
		return nil, fmt.Errorf("cloudkit: record/sync %s: no response", zone)
	}
	return result.Body, nil
}

func (c *Client) recordSyncZoneOnce(zone string, token []byte) (*types.HTTPResult, error) {
	header := BuildCodeInvokeHeader(c.auth.Header)
	body := octagon.FrameCodeInvoke(buildRecordSyncBody(zone, c.cfg.UserID, header, token))

	headers := buildHeaders(c.auth, c.cfg.UserID)
	headers["Content-Type"] = "application/x-protobuf"
	headers["Accept"] = "application/x-protobuf"

	return http.ExecuteRequest(c.cfg.DatabaseURL+"/api/client/record/sync",
		http.Method("POST"),
		http.Body(body),
		http.Headers(headers),
		http.Timeout(90*time.Second),
	)
}
