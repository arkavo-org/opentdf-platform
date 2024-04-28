package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"github.com/arkavo-org/opentdf-platform/protocol/go/authorization"
	"github.com/arkavo-org/opentdf-platform/protocol/go/policy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"log"
	"os"
)

func main() {
	// Load the client's certificate and private key
	certificate, err := tls.LoadX509KeyPair("../pep.crt", "../pep.key")
	if err != nil {
		log.Fatalf("could not load client key pair: %s", err)
	}

	// Create a certificate pool from the certificate authority
	certPool := x509.NewCertPool()
	ca, err := os.ReadFile("../ca.crt")
	if err != nil {
		log.Fatalf("could not read ca certificate: %s", err)
	}

	// Append the client certificates from the CA
	if ok := certPool.AppendCertsFromPEM(ca); !ok {
		log.Fatalf("failed to append client certs")
	}

	// Create the credentials and return it
	config := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		RootCAs:      certPool,
	}

	conn, err := grpc.Dial("localhost:8443",
		grpc.WithTransportCredentials(credentials.NewTLS(config)))
	if err != nil {
		log.Fatalf("did not connect: %s", err)
	}
	defer conn.Close()

	// Now you can use this `conn` to create your client, ex:
	// client := pb.NewYourServiceClient(conn)
	client := authorization.NewAuthorizationServiceClient(conn)
	drs := make([]*authorization.DecisionRequest, 0)
	drs = append(drs, &authorization.DecisionRequest{
		Actions:      make([]*policy.Action, 0),
		EntityChains: make([]*authorization.EntityChain, 0),
		ResourceAttributes: []*authorization.ResourceAttribute{
			{AttributeValueFqns: []string{}},
		},
	})

	decisionRequest := &authorization.GetDecisionsRequest{DecisionRequests: drs}
	ctx := context.Background()
	_, err = client.GetDecisions(ctx, decisionRequest)
	if err != nil {
		log.Fatalf("GetDecisions failed: %s", err)
	}
}
