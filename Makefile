
all: client server ids

./pkg/example/server.pb.go: ./api/server.proto
	protoc --go_out=plugins=grpc:. -I api server.proto

client: ./cmd/client/*.go ./pkg/example/server.pb.go
	go build -o client ./cmd/client/...

server: ./cmd/server/*.go ./pkg/example/server.pb.go
	go build -o server ./cmd/server/...

joe_id:
	ssh-keygen -P '' -b 2048  -t rsa  -f joe_id -m pem
	ssh-keygen -f joe_id.pub -m pkcs8 -e >joe_id.pkcs8

mary_id:
	ssh-keygen -P '' -b 2048  -t rsa  -f mary_id -m pem
	ssh-keygen -f mary_id.pub -m pkcs8 -e >mary_id.pkcs8

ids: joe_id mary_id

clean:
	rm -rf ./pkg/example client server joe_id* mary_id*
