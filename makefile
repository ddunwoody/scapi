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
CFLAGS=-fPIC
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
	@cp -r lib/CryptoPP build/CryptoPP
	@$(MAKE) -C build/CryptoPP CXXFLAGS=$(CXXFLAGS)
	@$(MAKE) -C build/CryptoPP CXXFLAGS=$(CXXFLAGS) dynamic
	@sudo $(MAKE) -C build/CryptoPP CXXFLAGS=$(CXXFLAGS) install

compile-miracl:
	@echo "Compiling the Miracl library..."
	@$(MAKE) -C build/Miracl MIRACL_TARGET_LANG=c
	@echo "Installing the Miracl library..."
	@sudo $(MAKE) -C build/Miracl MIRACL_TARGET_LANG=c install
	@$(MAKE) clean-miracl

compile-miracl-cpp:
	@echo "Compiling the Miracl library..."
	@$(MAKE) -C build/Miracl MIRACL_TARGET_LANG=cpp
	@echo "Installing the Miracl library..."
	@sudo $(MAKE) -C build/Miracl MIRACL_TARGET_LANG=cpp install
	@$(MAKE) clean-miracl

compile-otextension:
	@echo "Compiling the OtExtension library..."
	@cp -r lib/OTExtension build/OTExtension
	@sudo $(MAKE) -C build/OTExtension
	@sudo $(MAKE) -C build/OTExtension install

# TODO: add GMP and GF2X
compile-ntl:
	@echo "Compiling the NTL library..."
	@cp -r lib/NTL/unix build/NTL
	@cd build/NTL/src/ && ./configure SHARED=on
	@$(MAKE) -C build/NTL
	@$(MAKE) -C build/NTL install

compile-openssl:
	@echo "Compiling the OpenSSL library..."
	@cp -r lib/OpenSSL build/OpenSSL
	@cd build/OpenSSL && ./config shared -fPIC --openssldir=/usr/local/ssl
	@$(MAKE) -C build/OpenSSL depend
	@$(MAKE) -C build/OpenSSL all
	@sudo $(MAKE) -C build/OpenSSL install

compile-bouncycastle:
	@echo "Compiling the BouncyCastle library..."
	@cp -r lib/BouncyCastle build/BouncyCastle
	@cd build/BouncyCastle && chmod a+x build15+ && ./build15+
	@mkdir -p build/BouncyCastle/jars/
	@cp build/BouncyCastle/build/artifacts/jdk1.5/jars/bcprov-jdk* build/BouncyCastle/jars/
#@sudo apt-get install junit

jni-cryptopp: compile-cryptopp
	@echo "Compiling the Crypto++ jni interface..."
	@$(MAKE) -C src/jni/CryptoPPJavaInterface

jni-miracl: prepare-miracl compile-miracl
	@echo "Compiling the Miracl jni interface..."
	@$(MAKE) -C src/jni/MiraclJavaInterface

jni-otextension: prepare-miracl compile-miracl-cpp compile-otextension
	@echo "Compiling the OtExtension jni interface..."
	@$(MAKE) -C src/jni/OtExtensionJavaInterface

jni-ntl: clean-ntl compile-ntl
	@echo "Compiling the NTL jni interface..."
	@$(MAKE) -C src/jni/NTLJavaInterface

jni-openssl:
	@echo "Compiling the OpenSSL jni interface..."
	@$(MAKE) -C src/jni/OpenSSLJavaInterface

# clean targets
clean-cryptopp:
	@echo "Cleaning the cryptopp build dir..."
	@rm -rf build/CryptoPP

clean-miracl:
	@echo "Cleaning the miracl build dir..."
	@rm -rf build/Miracl

clean-otextension:
	@echo "Cleaning the otextension build dir..."
	@rm -rf build/OTExtension

clean-ntl:
	@echo "Cleaning the ntl build dir..."
	@rm -rf build/NTL

clean-openssl:
	@echo "Cleaning the openssl build dir..."
	@rm -rf build/OpenSSL

clean-bouncycastle:
	@echo "Cleaning the bouncycastle build dir..."
	@rm -rf build/BouncyCastle

prepare-miracl: clean-miracl
	@echo "Copying the miracl source files into the miracl build dir..."
	@mkdir -p build/Miracl
	@find lib/Miracl/ -type f -exec cp '{}' build/Miracl/ \;
	@rm -f build/Miracl/mirdef.h
	@rm -f build/Miracl/mrmuldv.c
	@cp -r lib/MiraclCompilation/* build/Miracl/

clean-jni-openssl:
	@echo "Cleaning the OpenSSL jni dir..."
	@$(MAKE) -C src/jni/OpenSSLJavaInterface clean

clean: clean-cryptopp clean-miracl clean-otextension clean-ntl clean-openssl
