BUILDFLAGS := -trimpath 
export OUTPUT_PATH := ../../build/

all: clean build

build: 
	$(MAKE) -C cmd/checkmate-plugin-registry OUTPUTH_PATH=$(OUTPUT_PATH)
	$(MAKE) -C cmd/plugins OUTPUTH_PATH=$(OUTPUT_PATH)

clean:
	rm -rf build


