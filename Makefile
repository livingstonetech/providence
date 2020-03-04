# Compiler and release flags
C=go
CFLAGS=build
LDFLAGS="-s -w"

# Directory structure
BUILD_DIR=build
RELEASE_DIR=release
DEBUG_DIR=debug
LINUX_DIR=linux
DARWIN_DIR=darwin

# Executable names
BASE=providence
OS_LINUX=linux
OS_DARWIN=darwin
EXEC_DEBUG_LINUX=$(BASE)_debug_linux
EXEC_DEBUG_DARWIN=$(BASE)_debug_darwin
EXEC_RELEASE_LINUX=$(BASE)_release_linux
EXEC_RELEASE_DARWIN=$(BASE)_release_darwin

# Codesigning (Required for Mac)
ENTITLEMENTS_FILE=entitlements.xml
CERTIFICATE_NAME="Mac Developer"

all:
	make debug-darwin
	make debug-linux
	make release-darwin
	make release-linux

test:
	go test ./... -v

clean:
	rm $(BUILD_DIR)/$(DEBUG_DIR)/$(EXEC_DEBUG_LINUX)
	rm $(BUILD_DIR)/$(DEBUG_DIR)/$(EXEC_DEBUG_DARWIN)
	rm $(BUILD_DIR)/$(RELEASE_DIR)/$(EXEC_RELEASE_LINUX)
	rm $(BUILD_DIR)/$(RELEASE_DIR)/$(EXEC_RELEASE_DARWIN)

debug-darwin:
	GOOS=darwin $(C) $(CFLAGS) -o $(BUILD_DIR)/$(DEBUG_DIR)/$(EXEC_DEBUG_DARWIN)
	codesign -s $(CERTIFICATE_NAME) --entitlements $(ENTITLEMENTS_FILE) $(BUILD_DIR)/$(DEBUG_DIR)/$(EXEC_DEBUG_DARWIN)

debug-linux:
	GOOS=linux $(C) $(CFLAGS) -o $(BUILD_DIR)/$(DEBUG_DIR)/$(EXEC_DEBUG_LINUX)

release-darwin:
	GOOS=darwin $(C) $(CFLAGS) -ldflags $(LDFLAGS) -o $(BUILD_DIR)/$(RELEASE_DIR)/$(EXEC_RELEASE_DARWIN)
	codesign -s $(CERTIFICATE_NAME) --entitlements $(ENTITLEMENTS_FILE) $(BUILD_DIR)/$(RELEASE_DIR)/$(EXEC_RELEASE_DARWIN)

release-linux:
	GOOS=linux $(C) $(CFLAGS) -ldflags $(LDFLAGS) -o $(BUILD_DIR)/$(RELEASE_DIR)/$(EXEC_RELEASE_LINUX)

run:
	go run main.go