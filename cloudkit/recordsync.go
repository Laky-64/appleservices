package cloudkit

import (
	"fmt"
	"time"

	"github.com/Laky-64/http"

	"github.com/Laky-64/appleservices/internal/protobuf"
	"github.com/Laky-64/appleservices/internal/uuid"
	"github.com/Laky-64/appleservices/octagon"
)

func buildRecordSyncBody(zone, userID string, header []byte) []byte {
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

func (c *Client) RecordSyncZone(zone string) ([]byte, error) {
	header := BuildCodeInvokeHeader(c.auth.Header)
	body := octagon.FrameCodeInvoke(buildRecordSyncBody(zone, c.cfg.UserID, header))

	headers := buildHeaders(c.auth, c.cfg.UserID)
	headers["Content-Type"] = "application/x-protobuf"
	headers["Accept"] = "application/x-protobuf"

	result, err := http.ExecuteRequest(c.cfg.DatabaseURL+"/api/client/record/sync",
		http.Method("POST"),
		http.Body(body),
		http.Headers(headers),
		http.Timeout(90*time.Second),
	)
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
