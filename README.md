# JSON Web Token Example

This respository contains an example GRPC client/server that
uses JSON Web Tokens to provide client verification and 
role based authorizaton.

## TL;DR
```
make
./server &
./client
./client -write
```

## The Server

The server is a simple GRPC server with a GET and SET method
which can be authorized independently. The server is configured
with a set of users which are identified by a UID and a public
certificate. Users are then assigned to roles (i.e. reader and
writer).

The two methods supported by the server are assigned required
roles.

An interceptor is added to the server so that all incoming
requests are first forwarded to the interceptor. The interceptor
checks to see if authorization (JWT) metadata is part of the
context and if not rejects the request.

If the request contains JWT information then the JWT is validated
in that the cert is valid and that the claims in the request
are valid. If verification fails the request is rejected. If
verification succeeds the request is forwarded to the handler.

## The Client

The client is configured to "act" on behalf of a user with
a given private certification. the private certificate is used
to encode the JWT information so that if can be verified by
the server using the public certificate.

The JWT information is added to the client request via a
client side interceptor so once the connection is established
and the client interceptor inserted in the path not further
changes are required on the client.

## Play

By default the server is configured with two uses, `joe` and `mary`.
`joe` has the role reader and `mary` has the role writer. Each 
are associated with the respective public cert (`joe_id.pkcs8` and
`mary_id.pkcs8`).

The GET server method requires the `reader` role and the SET 
server method requires the `writer` role.

By default the client is configured with the user `joe` and 
the private key associated with the `joe` user, `joe_id`.
This can be changed to `mary` with the command line options
`-uid mary --priv mary_id`.

By default the client will call the server GET method. This can
be changed to SET with the command line option `-write`.

If the call successed `SUCCESS` will be logged to the console,
else an error will be logged to the console.

## Looking Forward

This is just a very simple example to demonstrate how JWT might be
add to an existing GRPC with minimal impact. JWT authorization
could be expanded with other claims so that a call could be 
validated to be from another VOLTHA component and acting on behalf
of a given user for authorization.
