revel auth via ldap
======

Authenticate via LDAP or local server


#Usage:
Include module in app.conf

module.revauth=github.com/lujiacn/revauth

```

Include module in conf/routes
```
module:revauth

#Configuration

// will authenticate via local mongoDB User model
grpcauth.method="local"

// will authenticate via grpc
grpcauth.method="grpc"

grpcauth.server=localhost
grpcauth.port=50051 
	grpcAuthServer, ok := revel.Config.String("grpcauth.server")
	if !ok {
		panic("Authenticate server not defined")

	}
	grpcAuthPort := revel.Config.StringDefault("grpcauth.port", "50051")
	grpcDial = grpcAuthServer + ":" + grpcAuthPort
```


