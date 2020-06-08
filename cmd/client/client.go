package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"time"

	pb "github.com/dbainbriciena/jwt-aaa/pkg/example"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/golang/protobuf/ptypes/empty"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// newAuthorizationInterceptor constructs a new authorizationIntercepter based on the given client information
func newAuthorizationInterceptor(uid string, keyFile string) (grpc.UnaryClientInterceptor, error) {
	keyBytes, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("ERROR: unable to read private key file '%s': %v\n", keyFile, err)
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("ERROR: unable to parse private key file '%s': %v\n", keyFile, err)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"uid": uid,
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(key)
	if err != nil {
		return nil, fmt.Errorf("ERROR: unable to sign JWT: %v\n", err)
	}

	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		authCtx := metadata.NewOutgoingContext(
			ctx,
			metadata.Pairs("jwt", tokenString))
		return invoker(authCtx, method, req, reply, cc, opts...)
	}, nil
}

func main() {

	addr := flag.String("addr", "127.0.0.1:2222", "server address")
	uid := flag.String("uid", "joe", "user to claim")
	writeOp := flag.Bool("write", false, "to a write operation")
	privKeyFile := flag.String("priv", "joe_id", "private key file")
	flag.Parse()

	// Create an authorization interceptor
	auth, err := newAuthorizationInterceptor(*uid, *privKeyFile)
	if err != nil {
		log.Fatalf("ERROR: unable to build authorizaton: %v\n", err)
	}

	// Create an connection with the specified authorization
	conn, err := grpc.Dial(*addr, grpc.WithInsecure(), grpc.WithUnaryInterceptor(auth), grpc.WithBlock())
	if err != nil {
		log.Fatalf("ERROR: Unable to connect to server '%s': %v", *addr, err)
	}
	defer conn.Close()
	c := pb.NewExampleClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if *writeOp {
		_, err = c.SetServiceValue(ctx, &empty.Empty{})
	} else {
		_, err = c.GetServiceValue(ctx, &empty.Empty{})
	}
	if err != nil {
		log.Fatalf("FAIL: could not greet: %v", err)
	}

	log.Println("SUCCESS")
}
