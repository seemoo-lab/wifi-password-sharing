BUILD_DIR := build
DERIVED_DATA_DIR := $(BUILD_DIR)/DerivedData

all: PWS-Grantor PWS-Requestor

PWS-Grantor:
	xcodebuild -scheme $@ -derivedDataPath $(DERIVED_DATA_DIR) build

PWS-Requestor:
	xcodebuild -scheme $@ -derivedDataPath $(DERIVED_DATA_DIR) build	

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean
