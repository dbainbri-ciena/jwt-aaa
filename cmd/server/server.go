package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"strings"

	pb "github.com/dbainbri-ciena/jwt-aaa/pkg/example"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/golang/protobuf/ptypes/empty"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// CustomClaim specifies the user that the client claims to be
type CustomClaim struct {
	UID string
}

// Valid if a UID is claimed
func (c *CustomClaim) Valid() error {
	if c.UID == "" {
		return errors.New("invalid claim")
	}
	return nil
}

type serverImpl struct {
	rbac map[string]*userInfo
}

// Security configuration that maps methods to required roles.
// Note: there is currently no role composition, but there
// could be.
var roleByMethod = map[string][]string{
	"/example.Example/GetServiceValue": []string{
		"reader",
		"writer",
	},
	"/example.Example/SetServiceValue": []string{
		"writer",
	},
}

// Configured RBAC information
type userInfo struct {
	KeyFile string
	key     interface{}
	Roles   []string
}

// match check if one of the "have" roles is in one of the
// "required" roles
func match(have []string, require []string) bool {
	for _, h := range have {
		for _, r := range require {
			if h == r {
				return true
			}
		}
	}
	return false
}

// authorizationInterceptor verifies the required token and then verifies that the
// user has the required role for a method
func (s *serverImpl) authorizationInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	log.Printf("INFO: AUTHORIZE '%s'\n", info.FullMethod)
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		log.Println("WARNING: incoming request without metadata")
		return &empty.Empty{}, errors.New("not authorized")
	}
	tokenString, ok := md["jwt"]
	if !ok {
		log.Println("WARNING: no JWT in metadata")
		return &empty.Empty{}, errors.New("not authorized")
	}

	claims := &CustomClaim{}
	_, err := jwt.ParseWithClaims(tokenString[0], claims, func(token *jwt.Token) (interface{}, error) {
		if claims.Valid() != nil {
			log.Printf("WARNING: REJECT call to '%s': no UID claim", info.FullMethod)
			return nil, errors.New("not authorized")
		}
		user, ok := s.rbac[claims.UID]
		if !ok {
			log.Printf("WARNING: REJECT '%s' for '%s', unconfigured user", claims.UID, info.FullMethod)
			return nil, errors.New("not authorized")
		}

		return user.key, nil
	})
	if err != nil {
		log.Printf("WARNING: REJECT call to '%s': %v\n", info.FullMethod, err)
		return &empty.Empty{}, errors.New("not authorized")
	}

	roles, ok := roleByMethod[info.FullMethod]
	if !ok {
		log.Printf("WARNING: REJECT '%s' for '%s',  not configured for security\n", claims.UID, info.FullMethod)
		return nil, errors.New("not authorized")
	}

	if !match(s.rbac[claims.UID].Roles, roles) {
		log.Printf("WARNING: REJECT '%s' for '%s',  does not have required role %s\n", claims.UID, info.FullMethod, roles)
		return nil, errors.New("not authorized")
	}

	log.Printf("INFO: AUTHORIZED '%s' for '%s'\n", claims.UID, info.FullMethod)

	return handler(ctx, req)
}

// SetServiceValue example write operation
func (s *serverImpl) SetServiceValue(ctx context.Context, null *empty.Empty) (*empty.Empty, error) {

	log.Println("SERVER - SET - INVOKED")
	return &empty.Empty{}, nil
}

/// GetServiceValue example read operation
func (s *serverImpl) GetServiceValue(ctx context.Context, null *empty.Empty) (*empty.Empty, error) {
	log.Println("SERVER - GET - INVOKED")

	return &empty.Empty{}, nil
}

// stringMap used for additive command line argument parsing
type stringMap map[string]string

func (s *stringMap) Set(value string) error {
	parts := strings.SplitN(value, ":", 2)
	if len(parts) != 2 {
		return errors.New("invalid user specification")
	}
	if *s == nil {
		*s = make(map[string]string)
	}
	(*s)[parts[0]] = parts[1]
	return nil
}

func (s *stringMap) String() string {
	b, _ := json.Marshal(*s)
	return string(b)
}

// stringArray used for additive command line argument parsing
type stringArray []string

func (s *stringArray) Set(value string) error {
	(*s) = append(*s, value)
	return nil
}
func (s *stringArray) String() string {
	b, _ := json.Marshal(*s)
	return string(b)
}

func (u *userInfo) String() string {
	b, _ := json.Marshal(*u)
	return string(b)
}

func main() {

	var users stringMap
	var readers, writers stringArray
	_ = users.Set("joe:joe_id.pkcs8")
	_ = users.Set("mary:mary_id.pkcs8")
	_ = readers.Set("joe")
	_ = writers.Set("mary")

	ep := flag.String("ep", "127.0.0.1:2222", "endpoint  on which to listen")
	flag.Var(&users, "u", "users and their public keys")
	flag.Var(&readers, "r", "users assigned the reader role")
	flag.Var(&writers, "w", "users assigned the writer role")
	flag.Parse()

	log.Printf("INFO: USERS: %s\n", users.String())
	log.Printf("INFO: READERS: %s\n", readers.String())
	log.Printf("INFO: WRITERS: %s\n", writers.String())

	// Create a server impl and load it with RBAC configuration
	impl := &serverImpl{
		rbac: make(map[string]*userInfo),
	}

	// Read and parse the user public keys
	for uid, pubKeyFile := range users {
		keyBytes, err := ioutil.ReadFile(pubKeyFile)
		if err != nil {
			log.Fatalf("ERROR: unable to read user %s's public key file '%s': %v\n", uid, pubKeyFile, err)
		}
		key, err := jwt.ParseRSAPublicKeyFromPEM(keyBytes)
		if err != nil {
			log.Fatalf("ERROR: unable to parse user %s's public key file '%s': %v\n", uid, pubKeyFile, err)
		}
		info, ok := impl.rbac[uid]
		if !ok {
			info = &userInfo{}
			impl.rbac[uid] = info
		}
		info.KeyFile = pubKeyFile
		info.key = key
	}

	// Assign users to roles
	for _, uid := range readers {
		info, ok := impl.rbac[uid]
		if !ok {
			log.Fatalf("ERROR: reader role specified for unknown user '%s'\n", uid)
		}
		info.Roles = append(info.Roles, "reader")
	}
	for _, uid := range writers {
		info, ok := impl.rbac[uid]
		if !ok {
			log.Fatalf("ERROR: writer role specified for unknown user '%s'\n", uid)
		}
		info.Roles = append(info.Roles, "writer")
	}

	log.Println("START SERVER")

	lis, err := net.Listen("tcp", *ep)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer(grpc.UnaryInterceptor(impl.authorizationInterceptor))
	pb.RegisterExampleServer(s, impl)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
