# detecting a unix os type: could be Linux, Darwin(Mac), FreeBSD, etc...
uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')
ARCH := $(shell getconf LONG_BIT)

ifeq ($(uname_S),Linux)
	JAVA_HOME=$(shell dirname $$(dirname $$(readlink -f `which javac`)))
	JAVA_INCLUDES=-I$(JAVA_HOME)/include/
endif

ifeq ($(uname_S),Darwin)
	JAVA_HOME=$(shell dirname $$(dirname $$(readlink `which javac`)))
	JAVA_INCLUDES=-I$(JAVA_HOME)/Headers/
endif

# compilation options
CC=gcc
CXX=g++
CXXFLAGS="-DNDEBUG -g -O2 -fPIC"

# export all variables that are used by child makefiles
export JAVA_HOME
export JAVA_INCLUDES
export uname_S
export ARCH

EXTERNAL_LIBS_TARGETS=compile-cryptopp compile-miracl compile-otextension compile-ntl compile-openssl
JNI_TAGRETS=jni-cryptopp jni-miracl jni-otextension jni-ntl jni-openssl

all: $(JNI_TAGRETS)

# compile and install the crypto++ lib:
# first compile the default target (test program + static lib)
# then also compile the dynamic lib, and finally install.
compile-cryptopp:
	@echo "Compiling the Crypto++ library..."
	@$(MAKE) -C lib/CryptoPP CXXFLAGS=$(CXXFLAGS)
	@$(MAKE) -C lib/CryptoPP CXXFLAGS=$(CXXFLAGS) dynamic
	@sudo $(MAKE) -C lib/CryptoPP CXXFLAGS=$(CXXFLAGS) install

compile-miracl:
	@echo "Compiling the Miracl library..."
	@$(MAKE) -C build/miracl MIRACL_TARGET_LANG=c
	@echo "Installing the Miracl library..."
	@sudo $(MAKE) -C build/miracl MIRACL_TARGET_LANG=c install
	@$(MAKE) clean-miracl

compile-miracl-cpp:
	@echo "Compiling the Miracl library..."
	@$(MAKE) -C build/miracl MIRACL_TARGET_LANG=cpp
	@echo "Installing the Miracl library..."
	@sudo $(MAKE) -C build/miracl MIRACL_TARGET_LANG=cpp install
	@$(MAKE) clean-miracl

compile-otextension:
	@echo "Compiling the OtExtension library..."

compile-ntl:
	@echo "Compiling the NTL library..."

compile-openssl:
	@echo "Compiling the OpenSSL library..."

jni-cryptopp: compile-cryptopp
	@echo "Compiling the Crypto++ jni interface..."
	@$(MAKE) -C src/jni/CryptoPPJavaInterface

# depends: prepare-miracl compile-miracl
jni-miracl:
	@echo "Compiling the Miracl jni interface..."
	@$(MAKE) -C src/jni/MiraclJavaInterface

jni-otextension: prepare-miracl compile-miracl-cpp compile-otextension
	@echo "Compiling the OtExtension jni interface..."

jni-ntl: compile-ntl
	@echo "Compiling the NTL jni interface..."

jni-openssl: compile-openssl
	@echo "Compiling the OpenSSL jni interface..."

clean-miracl:
	@echo "Cleaning the miracl build dir..."
	@rm -rf build/miracl

prepare-miracl: clean-miracl
	@echo "Copying the miracl source files into the miracl build dir..."
	@mkdir -p build/miracl
	@find lib/Miracl/ -type f -exec cp '{}' build/miracl/ \;
	@rm -f build/miracl/mirdef.h
	@rm -f build/miracl/mrmuldv.c
	@cp -r lib/MiraclCompilation/* build/miracl/
