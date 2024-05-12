package access

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"sync"

	kaspb "github.com/arkavo-org/opentdf-platform/protocol/go/kas"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	ErrCertificateEncode = Error("certificate encode error")
	ErrPublicKeyMarshal  = Error("public key marshal error")
	algorithmEc256       = "ec:secp256r1"
)

var ecCertCache sync.Map

func (p *Provider) LegacyPublicKey(ctx context.Context, in *kaspb.LegacyPublicKeyRequest) (*wrapperspb.StringValue, error) {
	algorithm := in.GetAlgorithm()
	var err error
	if p.CryptoProvider == nil {
		return nil, errors.Join(ErrConfig, status.Error(codes.Internal, "configuration error"))
	}
	if algorithm == algorithmEc256 {
		ecCertIDInf := p.Config.ExtraProps["eccertid"]
		ecCertID, ok := ecCertIDInf.(string)
		if !ok {
			return nil, errors.New("services.kas.eccertid is not a string")
		}
		if cert, exists := ecCertCache.Load(ecCertID); exists {
			return cert.(*wrapperspb.StringValue), nil
		}
		cert, err := p.CryptoProvider.ECCertificate(ecCertID)
		if err != nil {
			slog.ErrorContext(ctx, "CryptoProvider.ECPublicKey failed", "err", err)
			return nil, errors.Join(ErrConfig, status.Error(codes.Internal, "configuration error"))
		}
		// workaround for Error code 75497574.  [ec_key_pair.cpp:650] Failed to create X509 cert struct.error:04800066:PEM routines::bad end line
		cert += "\n"
		ecCertStringValue := &wrapperspb.StringValue{Value: cert}
		// Store the certificate in the cache
		ecCertCache.Store(ecCertID, ecCertStringValue)
		return ecCertStringValue, nil
	}
	cert, err := p.CryptoProvider.RSAPublicKey("unknown")
	if err != nil {
		slog.ErrorContext(ctx, "CryptoProvider.RSAPublicKey failed", "err", err)
		return nil, errors.Join(ErrConfig, status.Error(codes.Internal, "configuration error"))
	}
	// workaround for Error code 75497574.  [ec_key_pair.cpp:650] Failed to create X509 cert struct.error:04800066:PEM routines::bad end line
	cert += "\n"
	return &wrapperspb.StringValue{Value: cert}, nil
}

func (p *Provider) PublicKey(ctx context.Context, in *kaspb.PublicKeyRequest) (*kaspb.PublicKeyResponse, error) {
	algorithm := in.GetAlgorithm()
	if algorithm == algorithmEc256 {
		ecPublicKeyPem, err := p.CryptoProvider.ECPublicKey("unknown")
		if err != nil {
			slog.ErrorContext(ctx, "CryptoProvider.ECPublicKey failed", "err", err)
			return nil, errors.Join(ErrConfig, status.Error(codes.Internal, "configuration error"))
		}

		return &kaspb.PublicKeyResponse{PublicKey: ecPublicKeyPem}, nil
	}

	if in.GetFmt() == "jwk" {
		rsaPublicKeyPem, err := p.CryptoProvider.RSAPublicKeyAsJSON("unknown")
		if err != nil {
			slog.ErrorContext(ctx, "CryptoProvider.RSAPublicKey failed", "err", err)
			return nil, errors.Join(ErrConfig, status.Error(codes.Internal, "configuration error"))
		}

		return &kaspb.PublicKeyResponse{PublicKey: rsaPublicKeyPem}, nil
	}

	if in.GetFmt() == "pkcs8" {
		rsaPublicKeyPem, err := p.CryptoProvider.RSAPublicKey("unknown")
		if err != nil {
			slog.ErrorContext(ctx, "CryptoProvider.RSAPublicKey failed", "err", err)
			return nil, errors.Join(ErrConfig, status.Error(codes.Internal, "configuration error"))
		}
		return &kaspb.PublicKeyResponse{PublicKey: rsaPublicKeyPem}, nil
	}

	rsaPublicKeyPem, err := p.CryptoProvider.RSAPublicKey("unknown")
	if err != nil {
		slog.ErrorContext(ctx, "CryptoProvider.RSAPublicKey failed", "err", err)
		return nil, errors.Join(ErrConfig, status.Error(codes.Internal, "configuration error"))
	}

	return &kaspb.PublicKeyResponse{PublicKey: rsaPublicKeyPem}, nil
}

func exportRsaPublicKeyAsPemStr(pubkey *rsa.PublicKey) (string, error) {
	pubkeyBytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return "", errors.Join(ErrPublicKeyMarshal, err)
	}
	pubkeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:    "PUBLIC KEY",
			Headers: nil,
			Bytes:   pubkeyBytes,
		},
	)

	return string(pubkeyPem), nil
}

func exportEcPublicKeyAsPemStr(pubkey *ecdsa.PublicKey) (string, error) {
	pubkeyBytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return "", errors.Join(ErrPublicKeyMarshal, err)
	}
	pubkeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:    "PUBLIC KEY",
			Headers: nil,
			Bytes:   pubkeyBytes,
		},
	)

	return string(pubkeyPem), nil
}

func exportCertificateAsPemStr(cert *x509.Certificate) (string, error) {
	certBytes := cert.Raw
	certPem := pem.EncodeToMemory(
		&pem.Block{
			Type:    "CERTIFICATE",
			Headers: nil,
			Bytes:   certBytes,
		},
	)
	if certPem == nil {
		return "", ErrCertificateEncode
	}
	return string(certPem) + "\n", nil
}

type Error string

func (e Error) Error() string {
	return string(e)
}
