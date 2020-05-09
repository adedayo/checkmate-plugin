export BUILDFLAGS := '-trimpath -ldflags="-s -w"'
export OUTPUT_PATH := ../../build/
export PLUGIN_OUTPUT_PATH := ../build/

all: clean build

build: 
	$(MAKE) -C cmd/checkmate-plugin-registry OUTPUTH_PATH=$(OUTPUT_PATH) BUILDFLAGS=$(BUILDFLAGS)
	$(MAKE) -C secrets-finder PLUGIN_OUTPUTH_PATH=$(PLUGIN_OUTPUT_PATH) BUILDFLAGS=$(BUILDFLAGS)

clean:
	rm -rf build
	protoc -I proto proto/checkmate.proto --go_out=plugins=grpc:proto


