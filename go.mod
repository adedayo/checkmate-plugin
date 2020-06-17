module github.com/adedayo/checkmate-plugin

go 1.14

require (
	github.com/adedayo/checkmate-core v0.0.5
	github.com/golang/protobuf v1.4.2
	github.com/hashicorp/go-hclog v0.14.1
	github.com/hashicorp/go-plugin v1.3.0
	github.com/mitchellh/go-homedir v1.1.0
	github.com/spf13/cobra v1.0.0
	github.com/spf13/viper v1.7.0
	google.golang.org/grpc v1.29.1
	google.golang.org/protobuf v1.24.0
)

// replace github.com/adedayo/checkmate-core v0.0.5 => ../checkmate-core
