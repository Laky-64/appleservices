package anisette

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/coder/websocket"
)

func (c *Client) Provision(ctx context.Context, s *State) error {
	hdr := c.albertHeaders(*s)
	startURL, finishURL, err := lookupProvisioningURLs(hdr)
	if err != nil {
		return err
	}

	wsURL := strings.Replace(c.url, "https://", "wss://", 1)
	wsURL = strings.Replace(wsURL, "http://", "ws://", 1) + "/v3/provisioning_session"
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		return fmt.Errorf("anisette: ws dial: %w", err)
	}
	defer func(conn *websocket.Conn, code websocket.StatusCode, reason string) {
		_ = conn.Close(code, reason)
	}(conn, websocket.StatusInternalError, "")

	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			return fmt.Errorf("anisette: ws read: %w", err)
		}
		var msg struct {
			Result string `json:"result"`
			CPIM   string `json:"cpim"`
			AdiPB  string `json:"adi_pb"`
		}
		if err := json.Unmarshal(data, &msg); err != nil {
			return fmt.Errorf("anisette: ws message decode: %w", err)
		}
		switch msg.Result {
		case "GiveIdentifier":
			if err := wsSend(ctx, conn, map[string]string{
				"identifier": base64.StdEncoding.EncodeToString(s.Identifier),
			}); err != nil {
				return err
			}
		case "GiveStartProvisioningData":
			spim, err := startProvisioning(startURL, c.albertHeaders(*s))
			if err != nil {
				return err
			}
			if err := wsSend(ctx, conn, map[string]string{"spim": spim}); err != nil {
				return err
			}
		case "GiveEndProvisioningData":
			ptm, tk, err := finishProvisioning(finishURL, c.albertHeaders(*s), msg.CPIM)
			if err != nil {
				return err
			}
			if err := wsSend(ctx, conn, map[string]string{"ptm": ptm, "tk": tk}); err != nil {
				return err
			}
		case "ProvisioningSuccess":
			adi, err := base64.StdEncoding.DecodeString(msg.AdiPB)
			if err != nil {
				return fmt.Errorf("anisette: decode adi_pb: %w", err)
			}
			s.AdiPB = adi
			_ = conn.Close(websocket.StatusNormalClosure, "")
			return nil
		default:
			return fmt.Errorf("anisette: unexpected provisioning message %q", msg.Result)
		}
	}
}

func wsSend(ctx context.Context, conn *websocket.Conn, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return conn.Write(ctx, websocket.MessageText, data)
}
