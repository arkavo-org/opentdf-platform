package audit

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	sdkAudit "github.com/opentdf/platform/sdk/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"
)

func quietInterceptor() connect.UnaryInterceptorFunc {
	return ContextServerInterceptor(slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil)))
}

func TestContextServerInterceptor_SetsRequestIDKey(t *testing.T) {
	for name, header := range map[string]string{"generated": "", "from header": uuid.NewString()} {
		t.Run(name, func(t *testing.T) {
			req := connect.NewRequest(&emptypb.Empty{})
			if header != "" {
				req.Header().Set(sdkAudit.RequestIDHeaderKey.String(), header)
			}
			var fromKey uuid.UUID
			var recorded uuid.UUID
			next := connect.UnaryFunc(func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
				fromKey, _ = ctx.Value(sdkAudit.RequestIDContextKey).(uuid.UUID)
				recorded = GetAuditDataFromContext(ctx).RequestID
				return connect.NewResponse(&emptypb.Empty{}), nil
			})
			_, err := quietInterceptor()(next)(t.Context(), req)
			require.NoError(t, err)
			assert.NotEqual(t, uuid.Nil, fromKey)
			assert.Equal(t, recorded, fromKey)
			if header != "" {
				assert.Equal(t, header, fromKey.String())
			}
		})
	}
}

// A handler's outgoing call through the SDK metadata interceptor reaches a
// second server whose transaction records the same request ID.
func TestContextServerInterceptor_RequestIDRoundTrip(t *testing.T) {
	var inner uuid.UUID
	mux := http.NewServeMux()
	mux.Handle("/inner", connect.NewUnaryHandler("/inner", func(ctx context.Context, _ *connect.Request[emptypb.Empty]) (*connect.Response[emptypb.Empty], error) {
		inner = GetAuditDataFromContext(ctx).RequestID
		return connect.NewResponse(&emptypb.Empty{}), nil
	}, connect.WithInterceptors(quietInterceptor())))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	client := connect.NewClient[emptypb.Empty, emptypb.Empty](srv.Client(), srv.URL+"/inner",
		connect.WithInterceptors(sdkAudit.MetadataAddingConnectInterceptor()))

	var outer uuid.UUID
	next := connect.UnaryFunc(func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		outer = GetAuditDataFromContext(ctx).RequestID
		_, err := client.CallUnary(ctx, connect.NewRequest(&emptypb.Empty{}))
		return connect.NewResponse(&emptypb.Empty{}), err
	})
	_, err := quietInterceptor()(next)(t.Context(), connect.NewRequest(&emptypb.Empty{}))
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, outer)
	assert.Equal(t, outer, inner)
}
