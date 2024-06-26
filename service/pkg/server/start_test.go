package server

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/arkavo-org/opentdf-platform/service/internal/auth"
	"github.com/arkavo-org/opentdf-platform/service/internal/config"
	"github.com/arkavo-org/opentdf-platform/service/internal/db"
	"github.com/arkavo-org/opentdf-platform/service/internal/server"
	"github.com/arkavo-org/opentdf-platform/service/pkg/serviceregistry"
	"github.com/docker/go-connections/nat"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/exp/slog"
	"google.golang.org/grpc"
)

type TestServiceService interface{}
type TestService struct{}

func (t TestService) TestHandler(w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
	_, err := w.Write([]byte("hello from test service!"))
	if err != nil {
		panic(err)
	}
}

func ServiceRegistrationTest() serviceregistry.Registration {
	return serviceregistry.Registration{
		Namespace: "test",
		ServiceDesc: &grpc.ServiceDesc{
			ServiceName: "TestService",
			HandlerType: (*TestServiceService)(nil),
		},
		RegisterFunc: func(srp serviceregistry.RegistrationParams) (any, serviceregistry.HandlerServer) {
			return &TestService{}, func(ctx context.Context, mux *runtime.ServeMux, server any) error {
				t, ok := server.(*TestService)
				if !ok {
					return fmt.Errorf("Surprise! Not a TestService")
				}
				return mux.HandlePath(http.MethodGet, "/healthz", t.TestHandler)
			}
		},
	}
}

func Test_Start_When_Extra_Service_Registered_Expect_Response(t *testing.T) {
	discoveryURL := "not set yet"

	discoveryEndpoint := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			var resp string
			switch req.URL.Path {
			case "/.well-known/openid-configuration":
				resp = `{
					"issuer":	"https://example.com",
					"authorization_endpoint":	"https://example.com/oauth2/v1/authorize",
					"token_endpoint":	"https://example.com/oauth2/v1/token",
					"userinfo_endpoint": "https://example.com/oauth2/v1/userinfo",
					"registration_endpoint": "https://example.com/oauth2/v1/clients",
					"jwks_uri": "` + discoveryURL + `/oauth2/v1/keys"
				}`
			case "/oauth2/v1/keys":
				resp = `{
					"keys":[{"kty":"RSA","alg":"RS256","kid":"saqvCEEc1QX1kjGRh3sf0o4bdPMiiQBVj9xYz95M-X0","use":"sig","e":"AQAB","n":"yXgJvKqNfKoOoc1KiTg8QYfAO2AA47PjHtqZFsPSh93FI3tobD52t1I9cbD7ZotIYfYmZ6KwDvtrAIMVAPKvqvVUji3xSsNQ_Vv4XRmoWwP1vgJNJxoHOyj7pfDdhjplZZaQEcEEpm_J9rXN6V2lLyL6zYLJr_SlI5JeMc8i0tigFW_yLTUpSQ_85r5fAvkr0VDeUHfonaueaFhF5r-fne-F9EZzAVZvG3P8IG8_K6NEoM6muzsplPWJ-95hheRa3Zh58vYTVHcX8DXd8rpS3laUlLuEmIVs-FlqYrIBKpP2spQYGRvf-P1wpNftMH7OTB4j6ULQjwlNRmiQ34TOhw"}]
				}`
			default:
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(resp))
		}),
	)

	discoveryURL = discoveryEndpoint.URL

	// Create new opentdf server
	d, _ := db.NewClient(db.Config{})
	s, err := server.NewOpenTDFServer(server.Config{
		WellKnownConfigRegister: func(namespace string, config any) error {
			return nil
		},
		Auth: auth.Config{
			AuthNConfig: auth.AuthNConfig{
				Issuer:   discoveryEndpoint.URL,
				Audience: "test",
			},
			PublicRoutes: []string{"/testpath/*"},
		},
		Port: 43481,
	}, d)
	require.NoError(t, err)

	// Register Test Service
	err = serviceregistry.RegisterService(ServiceRegistrationTest())
	require.NoError(t, err)

	// Start services with test service
	err = startServices(config.Config{
		Services: map[string]serviceregistry.ServiceConfig{
			"test": {
				Enabled: true,
			},
		},
	}, s, nil, nil, nil)
	require.NoError(t, err)

	s.Start()

	defer s.Stop()

	var resp *http.Response
	// Make request to test service and ensure it registered
	for i := 3; i > 0; i-- {
		resp, err = http.Get("http://localhost:43481/healthz")
		if err == nil {
			break
		}
		slog.Info("not yet ready", "err", err)
		// retry after a blip
		time.Sleep(100 * time.Millisecond)
	}

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	respBody, err := io.ReadAll(resp.Body)

	require.NoError(t, err)
	assert.Equal(t, "hello from test service!", string(respBody))
}

func startWireMock() (tc.Container, error) {
	var providerType tc.ProviderType

	if os.Getenv("TESTCONTAINERS_PODMAN") == "true" {
		providerType = tc.ProviderPodman
	} else {
		providerType = tc.ProviderDocker
	}

	listenPort, _ := nat.NewPort("tcp", "8184")

	req := tc.ContainerRequest{
		FromDockerfile: tc.FromDockerfile{
			Repo:       "platform/mocks",
			KeepImage:  true,
			Context:    "../../integration/wiremock",
			Dockerfile: "Dockerfile",
		},
		ExposedPorts: []string{fmt.Sprintf("%s/tcp", listenPort.Port())},
		Cmd:          []string{fmt.Sprintf("--port=%s", listenPort.Port()), "--verbose"},
		WaitingFor:   wait.ForLog("extensions:"),
		Files: []tc.ContainerFile{
			{
				HostFilePath:      "../../integration/wiremock/mappings",
				ContainerFilePath: "/home/wiremock/mappings",
				FileMode:          0o444,
			},
			{
				HostFilePath:      "../../integration/wiremock/messages",
				ContainerFilePath: "/home/wiremock/__files/messages",
				FileMode:          0o444,
			},
			{
				HostFilePath:      "../../integration/wiremock/grpc",
				ContainerFilePath: "/home/wiremock/grpc",
				FileMode:          0o444,
			},
		},
	}

	return tc.GenericContainer(context.Background(), tc.GenericContainerRequest{
		ProviderType:     providerType,
		ContainerRequest: req,
		Started:          true,
	})
}
