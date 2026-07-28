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

const recordSaveType = 210

type SaveResult struct {
	Code        int
	ClientCode  int
	ServerCode  int
	Description string
	Etag        string
}

const resultCodeSuccess = 1

type SaveError struct{ SaveResult }

func (e *SaveError) Error() string {
	return fmt.Sprintf("cloudkit: record/save result code %d (clientErr=%d serverErr=%d): %s",
		e.Code, e.ClientCode, e.ServerCode, e.Description)
}

func (e *SaveError) AlreadyExists() bool { return e.ClientCode == 9 }

func buildRecordSaveBody(recordSaveRequest []byte, header []byte) []byte {
	op := protobuf.NewWriter()
	op.WriteBytes(1, []byte(uuid.New()))
	op.WriteVarint(2, recordSaveType)
	op.WriteVarint(4, 1)

	reqOp := protobuf.NewWriter()
	if header != nil {
		reqOp.WriteBytes(1, header)
	}
	reqOp.WriteBytes(2, op.Bytes())
	reqOp.WriteBytes(recordSaveType, recordSaveRequest)
	return reqOp.Bytes()
}

func (c *Client) RecordSave(recordSaveRequest []byte) (SaveResult, error) {
	result, err := c.recordSaveOnce(recordSaveRequest)
	if result != nil && result.StatusCode == statusUnauthorized && c.reauthenticate() {
		result, err = c.recordSaveOnce(recordSaveRequest)
	}
	if result != nil && result.StatusCode != 200 {
		return SaveResult{}, fmt.Errorf("cloudkit: record/save status %d: %s", result.StatusCode, snippet(result.Body))
	}
	if err != nil {
		return SaveResult{}, fmt.Errorf("cloudkit: record/save: %w", err)
	}
	if result == nil {
		return SaveResult{}, fmt.Errorf("cloudkit: record/save: no response")
	}

	sr, err := parseSaveResult(result.Body)
	if err != nil {
		return SaveResult{}, fmt.Errorf("cloudkit: record/save decode: %w", err)
	}
	if sr.Code != resultCodeSuccess {
		return sr, &SaveError{sr}
	}
	return sr, nil
}

func (c *Client) recordSaveOnce(recordSaveRequest []byte) (*types.HTTPResult, error) {
	header := BuildCodeInvokeHeader(c.auth.Header)
	body := octagon.FrameCodeInvoke(buildRecordSaveBody(recordSaveRequest, header))

	headers := buildHeaders(c.auth, c.cfg.UserID)
	headers["Content-Type"] = "application/x-protobuf"
	headers["Accept"] = "application/x-protobuf"

	return http.ExecuteRequest(c.cfg.DatabaseURL+"/api/client/record/save",
		http.Method("POST"),
		http.Body(body),
		http.Headers(headers),
		http.Timeout(90*time.Second),
	)
}

func (c *Client) UserID() string { return c.cfg.UserID }

func parseSaveResult(raw []byte) (SaveResult, error) {
	msg := raw
	if m, err := octagon.UnframeCodeInvoke(raw); err == nil {
		msg = m
	}
	fields, err := protobuf.ReadFields(msg)
	if err != nil {
		return SaveResult{}, err
	}

	var sr SaveResult
	for _, f := range fields {
		switch {
		case f.Number == 3 && f.WireType == protobuf.WireBytes:
			if err := parseResult(f.Bytes, &sr); err != nil {
				return SaveResult{}, err
			}
		case f.Number == recordSaveType && f.WireType == protobuf.WireBytes:
			sr.Etag = recordSaveResponseEtag(f.Bytes)
		}
	}
	return sr, nil
}

func parseResult(b []byte, sr *SaveResult) error {
	rf, err := protobuf.ReadFields(b)
	if err != nil {
		return err
	}
	for _, f := range rf {
		switch {
		case f.Number == 1 && f.WireType == protobuf.WireVarint:
			sr.Code = int(f.Varint)
		case f.Number == 2 && f.WireType == protobuf.WireBytes:
			parseResultError(f.Bytes, sr)
		}
	}
	return nil
}

func parseResultError(b []byte, sr *SaveResult) {
	ef, err := protobuf.ReadFields(b)
	if err != nil {
		return
	}
	for _, f := range ef {
		switch {
		case f.Number == 1 && f.WireType == protobuf.WireBytes:
			sr.ClientCode = errorType(f.Bytes)
		case f.Number == 2 && f.WireType == protobuf.WireBytes:
			sr.ServerCode = errorType(f.Bytes)
		case f.Number == 4 && f.WireType == protobuf.WireBytes:
			sr.Description = string(f.Bytes)
		}
	}
}

func errorType(b []byte) int {
	fs, err := protobuf.ReadFields(b)
	if err != nil {
		return 0
	}
	for _, f := range fs {
		if f.Number == 1 && f.WireType == protobuf.WireVarint {
			return int(f.Varint)
		}
	}
	return 0
}

func recordSaveResponseEtag(b []byte) string {
	fs, err := protobuf.ReadFields(b)
	if err != nil {
		return ""
	}
	for _, f := range fs {
		if f.Number == 2 && f.WireType == protobuf.WireBytes {
			return string(f.Bytes)
		}
	}
	return ""
}
