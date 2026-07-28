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

const recordDeleteType = 214

func buildRecordDeleteBody(recordDeleteRequest []byte, header []byte) []byte {
	op := protobuf.NewWriter()
	op.WriteBytes(1, []byte(uuid.New()))
	op.WriteVarint(2, recordDeleteType)
	op.WriteVarint(4, 1)

	reqOp := protobuf.NewWriter()
	if header != nil {
		reqOp.WriteBytes(1, header)
	}
	reqOp.WriteBytes(2, op.Bytes())
	reqOp.WriteBytes(recordDeleteType, recordDeleteRequest)
	return reqOp.Bytes()
}

func (c *Client) RecordDelete(recordDeleteRequest []byte) (SaveResult, error) {
	result, err := c.recordDeleteOnce(recordDeleteRequest)
	if result != nil && result.StatusCode == statusUnauthorized && c.reauthenticate() {
		result, err = c.recordDeleteOnce(recordDeleteRequest)
	}
	if result != nil && result.StatusCode != 200 {
		return SaveResult{}, fmt.Errorf("cloudkit: record/delete status %d: %s", result.StatusCode, snippet(result.Body))
	}
	if err != nil {
		return SaveResult{}, fmt.Errorf("cloudkit: record/delete: %w", err)
	}
	if result == nil {
		return SaveResult{}, fmt.Errorf("cloudkit: record/delete: no response")
	}
	sr, err := parseSaveResult(result.Body)
	if err != nil {
		return SaveResult{}, fmt.Errorf("cloudkit: record/delete decode: %w", err)
	}
	if sr.Code != resultCodeSuccess {
		return sr, &SaveError{sr}
	}
	return sr, nil
}

func (c *Client) recordDeleteOnce(recordDeleteRequest []byte) (*types.HTTPResult, error) {
	header := BuildCodeInvokeHeader(c.auth.Header)
	body := octagon.FrameCodeInvoke(buildRecordDeleteBody(recordDeleteRequest, header))

	headers := buildHeaders(c.auth, c.cfg.UserID)
	headers["Content-Type"] = "application/x-protobuf"
	headers["Accept"] = "application/x-protobuf"

	return http.ExecuteRequest(c.cfg.DatabaseURL+"/api/client/record/delete",
		http.Method("POST"),
		http.Body(body),
		http.Headers(headers),
		http.Timeout(90*time.Second),
	)
}
