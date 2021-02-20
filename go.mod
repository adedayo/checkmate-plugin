module github.com/adedayo/checkmate-plugin

go 1.15

require (
	github.com/adedayo/checkmate-core v0.1.2
	github.com/golang/protobuf v1.4.3
	github.com/hashicorp/go-hclog v0.15.0
	github.com/hashicorp/go-plugin v1.4.0
	github.com/mitchellh/go-homedir v1.1.0
	github.com/spf13/cobra v1.1.3
	github.com/spf13/viper v1.7.1
	google.golang.org/grpc v1.35.0
	google.golang.org/protobuf v1.25.0
)

// replace github.com/adedayo/checkmate-core v0.1.1 => ../checkmate-core
