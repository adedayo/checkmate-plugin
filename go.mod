module github.com/adedayo/checkmate-plugin

go 1.16

require (
	github.com/adedayo/checkmate-core v0.1.6
	github.com/golang/protobuf v1.5.1
	github.com/hashicorp/go-hclog v0.15.0
	github.com/hashicorp/go-plugin v1.4.0
	github.com/mitchellh/go-homedir v1.1.0
	github.com/spf13/cobra v1.1.3
	github.com/spf13/viper v1.7.1
	google.golang.org/grpc v1.36.0
	google.golang.org/protobuf v1.26.0
)

// replace github.com/adedayo/checkmate-core v0.1.5 => ../checkmate-core
