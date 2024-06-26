package sdk

import (
	"crypto/tls"
	"errors"
	"log/slog"

	"github.com/arkavo-org/opentdf-platform/protocol/go/authorization"
	"github.com/arkavo-org/opentdf-platform/protocol/go/policy/attributes"
	"github.com/arkavo-org/opentdf-platform/protocol/go/policy/kasregistry"
	"github.com/arkavo-org/opentdf-platform/protocol/go/policy/namespaces"
	"github.com/arkavo-org/opentdf-platform/protocol/go/policy/resourcemapping"
	"github.com/arkavo-org/opentdf-platform/protocol/go/policy/subjectmapping"
	"github.com/arkavo-org/opentdf-platform/sdk/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	ErrGrpcDialFailed = Error("failed to dial grpc endpoint")
	ErrShutdownFailed = Error("failed to shutdown sdk")
)

type Error string

func (c Error) Error() string {
	return string(c)
}

type SDK struct {
	conn                    *grpc.ClientConn
	dialOptions             []grpc.DialOption
	tokenSource             auth.AccessTokenSource
	Namespaces              namespaces.NamespaceServiceClient
	Attributes              attributes.AttributesServiceClient
	ResourceMapping         resourcemapping.ResourceMappingServiceClient
	SubjectMapping          subjectmapping.SubjectMappingServiceClient
	KeyAccessServerRegistry kasregistry.KeyAccessServerRegistryServiceClient
	Authorization           authorization.AuthorizationServiceClient
}

func New(platformEndpoint string, opts ...Option) (*SDK, error) {
	tlsConfig := tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Set default options
	cfg := &config{
		tls: grpc.WithTransportCredentials(credentials.NewTLS(&tlsConfig)),
	}

	// Apply options
	for _, opt := range opts {
		opt(cfg)
	}

	// once we change KAS to use standard DPoP we can put this all in the `build()` method
	dialOptions := append([]grpc.DialOption{}, cfg.build()...)
	// Add extra grpc dial options if provided. This is useful during tests.
	if len(cfg.extraDialOptions) > 0 {
		dialOptions = append(dialOptions, cfg.extraDialOptions...)
	}

	accessTokenSource, err := buildIDPTokenSource(cfg)
	if err != nil {
		return nil, err
	}
	if accessTokenSource != nil {
		interceptor := auth.NewTokenAddingInterceptor(accessTokenSource)
		dialOptions = append(dialOptions, grpc.WithUnaryInterceptor(interceptor.AddCredentials))
	}

	var (
		defaultConn       *grpc.ClientConn
		policyConn        *grpc.ClientConn
		authorizationConn *grpc.ClientConn
	)

	if platformEndpoint != "" {
		var err error
		defaultConn, err = grpc.Dial(platformEndpoint, dialOptions...)
		if err != nil {
			return nil, errors.Join(ErrGrpcDialFailed, err)
		}
	}

	if cfg.policyConn != nil {
		policyConn = cfg.policyConn
	} else {
		policyConn = defaultConn
	}

	if cfg.authorizationConn != nil {
		authorizationConn = cfg.authorizationConn
	} else {
		authorizationConn = defaultConn
	}

	return &SDK{
		conn:                    defaultConn,
		dialOptions:             dialOptions,
		tokenSource:             accessTokenSource,
		Attributes:              attributes.NewAttributesServiceClient(policyConn),
		Namespaces:              namespaces.NewNamespaceServiceClient(policyConn),
		ResourceMapping:         resourcemapping.NewResourceMappingServiceClient(policyConn),
		SubjectMapping:          subjectmapping.NewSubjectMappingServiceClient(policyConn),
		KeyAccessServerRegistry: kasregistry.NewKeyAccessServerRegistryServiceClient(policyConn),
		Authorization:           authorization.NewAuthorizationServiceClient(authorizationConn),
	}, nil
}

func buildIDPTokenSource(c *config) (auth.AccessTokenSource, error) {
	if (c.clientCredentials == nil) != (c.tokenEndpoint == "") {
		return nil, errors.New("either both or neither of client credentials and token endpoint must be specified")
	}

	// at this point we have either both client credentials and a token endpoint or none of the above. if we don't have
	// any just return a KAS client that can only get public keys
	if c.clientCredentials == nil {
		slog.Info("no client credentials provided. GRPC requests to KAS and services will not be authenticated.")
		return nil, nil //nolint:nilnil // not having credentials is not an error
	}

	var ts auth.AccessTokenSource
	var err error
	if c.tokenExchange == nil {
		ts, err = NewIDPAccessTokenSource(
			*c.clientCredentials,
			c.tokenEndpoint,
			c.scopes,
		)
	} else {
		ts, err = NewIDPTokenExchangeTokenSource(
			*c.tokenExchange,
			*c.clientCredentials,
			c.tokenEndpoint,
			c.scopes,
		)
	}

	return ts, err
}

// Close closes the underlying grpc.ClientConn.
func (s SDK) Close() error {
	if s.conn == nil {
		return nil
	}
	if err := s.conn.Close(); err != nil {
		return errors.Join(ErrShutdownFailed, err)
	}
	return nil
}

// Conn returns the underlying grpc.ClientConn.
func (s SDK) Conn() *grpc.ClientConn {
	return s.conn
}
