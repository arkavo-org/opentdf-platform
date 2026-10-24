package authorization

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/policy/filestore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A binary that predates device_rules ignores the section silently, so the
// file store's load says at Info whether the policy file declares any, and
// how many.
func TestLogDeviceRules(t *testing.T) {
	for name, tc := range map[string]struct {
		path string
		msg  string
		want map[string]any
	}{
		"rules declared": {
			"../../entityresolution/composite/v2/testdata/policy.device-rules.yaml",
			"device_rules loaded",
			map[string]any{"requirements": 1.0, "caps": 1.0},
		},
		"none declared": {
			"../../../examples/config/policy.patreon.yaml",
			"device_rules: none declared in the policy file",
			map[string]any{},
		},
	} {
		t.Run(name, func(t *testing.T) {
			store, err := filestore.NewStoreFromFile(tc.path)
			require.NoError(t, err)
			buf := &bytes.Buffer{}
			bufLog := &logger.Logger{Logger: slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))}

			logDeviceRules(bufLog, tc.path, store.DeviceRules())

			var records []map[string]any
			for sc := bufio.NewScanner(buf); sc.Scan(); {
				var rec map[string]any
				require.NoError(t, json.Unmarshal(sc.Bytes(), &rec))
				records = append(records, rec)
			}
			require.Len(t, records, 1)
			rec := records[0]
			assert.Equal(t, "INFO", rec["level"])
			assert.Equal(t, tc.msg, rec["msg"])
			assert.Equal(t, tc.path, rec["path"])
			for key, v := range tc.want {
				assert.Equal(t, v, rec[key], key)
			}
		})
	}
}
