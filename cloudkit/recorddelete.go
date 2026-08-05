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

func buildRecordDeleteBatchBody(reqs [][]byte, header []byte) []byte {
	var body []byte
	for i, req := range reqs {
		op := protobuf.NewWriter()
		op.WriteBytes(1, []byte(uuid.New()))
		op.WriteVarint(2, recordDeleteType)
		if i == len(reqs)-1 {
			op.WriteVarint(4, 1)
		}

		reqOp := protobuf.NewWriter()
		if i == 0 && header != nil {
			reqOp.WriteBytes(1, header)
		}
		reqOp.WriteBytes(2, op.Bytes())
		reqOp.WriteBytes(recordDeleteType, req)
		body = append(body, octagon.FrameCodeInvoke(reqOp.Bytes())...)
	}
	return body
}

func foldBatchResponse(stream []byte, want int) ([]SaveResult, error) {
	results := make([]SaveResult, want)
	rest := stream
	for i := 0; i < want; i++ {
		if len(rest) == 0 {
			results[i] = SaveResult{Code: 4}
			continue
		}
		msg, next, err := octagon.NextCodeInvokeFrame(rest)
		if err != nil {
			if i == 0 {
				return nil, fmt.Errorf("cloudkit: record/delete batch response framing: %w", err)
			}
			results[i] = SaveResult{Code: 4}
			rest = nil
			continue
		}
		sr, err := parseSaveResult(msg)
		if err != nil {
			results[i] = SaveResult{Code: 4}
		} else {
			results[i] = sr
		}
		rest = next
	}
	return results, nil
}

func (c *Client) RecordDeleteBatch(reqs [][]byte) ([]SaveResult, error) {
	if len(reqs) == 0 {
		return nil, nil
	}
	result, err := c.recordDeleteBatchOnce(reqs)
	if result != nil && result.StatusCode == statusUnauthorized && c.reauthenticate() {
		result, err = c.recordDeleteBatchOnce(reqs)
	}
	if err != nil {
		return nil, fmt.Errorf("cloudkit: record/delete batch: %w", err)
	}
	if result == nil {
		return nil, fmt.Errorf("cloudkit: record/delete batch: no response")
	}
	if result.StatusCode != 200 {
		return nil, fmt.Errorf("cloudkit: record/delete batch status %d: %s", result.StatusCode, snippet(result.Body))
	}
	return foldBatchResponse(result.Body, len(reqs))
}

func (c *Client) recordDeleteBatchOnce(reqs [][]byte) (*types.HTTPResult, error) {
	header := BuildCodeInvokeHeader(c.auth.Header)
	body := buildRecordDeleteBatchBody(reqs, header)

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
