VERSION ?= 0.1

export GYP_GENERATOR_FLAGS = "xcode_project_version=3.2"
IOS_SDK ?= iphoneos
SIMULATOR_SDK ?= iphonesimulator
MACOSX_SDK ?= macosx
CONFIGURATION ?= Release
LIPO ?= `xcrun -find lipo -sdk $(IOS_SDK)`
OUTPUT_iphoneos ?= ./out/$(CONFIGURATION)/libscrypt-combined.a
OUTPUT_macosx ?= ./out/$(CONFIGURATION)/libscrypt-macosx.a
FRAMEWORK_NAME ?= scrypt
FRAMEWORK_OUTPUT ?= ./out/$(CONFIGURATION)/$$platform/$(FRAMEWORK_NAME).framework

CONFIGURATIONS = Debug Release
SUFFIXES = iphoneos iphonesimulator macosx
PLATFORMS = iphoneos macosx

all:
	@echo "Try 'make framework' if you are on OS X"

xcodeproj:
	./gyp_scrypt -f xcode -Dsdk=$(IOS_SDK) --suffix=-iphoneos
	./gyp_scrypt -f xcode -Dsdk=$(SIMULATOR_SDK) --suffix=-iphonesimulator
	./gyp_scrypt -f xcode -Dsdk=$(MACOSX_SDK) --suffix=-macosx

lipo: xcodeproj
	mkdir -p out/$(CONFIGURATION)
	for suffix in $(SUFFIXES) ; do \
		xcodebuild -configuration $(CONFIGURATION) \
			-project scrypt-$$suffix.xcodeproj ; \
	done
	$(LIPO) -create \
			./build/$(CONFIGURATION)-iphoneos/libscrypt.a \
			./build/$(CONFIGURATION)-iphonesimulator/libscrypt.a \
			-output $(OUTPUT_iphoneos)
	cp -a ./build/$(CONFIGURATION)/libscrypt.a \
		$(OUTPUT_macosx)

framework: lipo
	for platform in $(PLATFORMS) ; do \
		mkdir -p $(FRAMEWORK_OUTPUT)/Versions/$(VERSION)/Headers; \
		cp -af include/scrypt.h \
			$(FRAMEWORK_OUTPUT)/Versions/$(VERSION)/Headers/scrypt.h ; \
		ln -sfn $(VERSION) \
				$(FRAMEWORK_OUTPUT)/Versions/Current; \
		ln -sfn Versions/Current/Headers \
				$(FRAMEWORK_OUTPUT)/Headers; \
		ln -sfn Versions/Current/$(FRAMEWORK_NAME) \
				$(FRAMEWORK_OUTPUT)/$(FRAMEWORK_NAME); \
		if [[ $$platform = "iphoneos" ]]; then\
			cp -af $(OUTPUT_iphoneos) \
				$(FRAMEWORK_OUTPUT)/Versions/$(VERSION)/$(FRAMEWORK_NAME); \
		else \
			cp -af $(OUTPUT_macosx) \
				$(FRAMEWORK_OUTPUT)/Versions/$(VERSION)/$(FRAMEWORK_NAME); \
		fi \
	done

test:
	cd test && npm update && \
		(node server.js & \
		 (xcodebuild && ./build/Debug/test-runner || true) && \
		 kill $$!)

clean:
	for config in $(CONFIGURATIONS) ; do \
		for suffix in $(SUFFIXES) ; do \
			xcodebuild clean -configuration $$config \
				-project scrypt-$$suffix.xcodeproj ;\
			rm -rf ./build/$$config-$$suffix/libscrypt.a ;\
		done \
	done
	for platform in $(PLATFORMS) ; do \
		rm -rf $(FRAMEWORK_OUTPUT); \
	done
	rm -f $(OUTPUT_iphoneos) $(OUTPUT_macosx)

.PHONY: all clean xcodeproj lip framework test
