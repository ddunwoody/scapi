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

# target names
CLEAN_TARGETS:=clean-cryptopp clean-miracl clean-miracl-cpp clean-otextension clean-ntl clean-openssl clean-bouncycastle
CLEAN_JNI_TARGETS:=clean-jni-cryptopp clean-jni-miracl clean-jni-otextension clean-jni-ntl clean-jni-openssl

JNI_CRYPTOPP:=src/jni/CryptoPPJavaInterface/libCryptoPPJavaInterface.so
JNI_MIRACL:=src/jni/MiraclJavaInterface/libMiraclJavaInterface.so
JNI_OTEXTENSION:=src/jni/OtExtensionJavaInterface/libOtExtensionJavaInterface.so
JNI_NTL:=src/jni/NTLJavaInterface/libNTLJavaInterface.so
JNI_OPENSSL:=src/jni/OpenSSLJavaInterface/libOpenSSLJavaInterface.so
JAR_BOUNCYCASTLE:=build/BouncyCastle/jars/bcprov-jdk15on-151b18.jar

EXTERNAL_LIBS_TARGETS:=compile-cryptopp compile-miracl compile-otextension compile-ntl compile-openssl
JNI_TAGRETS=jni-cryptopp jni-miracl jni-otextension jni-ntl jni-openssl

all: $(JNI_TAGRETS) $(JAR_BOUNCYCASTLE)

# compile and install the crypto++ lib:
# first compile the default target (test program + static lib)
# then also compile the dynamic lib, and finally install.
compile-cryptopp:
	@echo "Compiling the Crypto++ library..."
	@cp -r lib/CryptoPP build/CryptoPP
	@$(MAKE) -C build/CryptoPP CXXFLAGS=$(CXXFLAGS)
	@$(MAKE) -C build/CryptoPP CXXFLAGS=$(CXXFLAGS) dynamic
	@sudo $(MAKE) -C build/CryptoPP CXXFLAGS=$(CXXFLAGS) install
	@touch compile-cryptopp

compile-miracl:
	@$(MAKE) prepare-miracl MIRACL_DIR=Miracl
	@echo "Compiling the Miracl library (C)..."
	@$(MAKE) -C build/Miracl MIRACL_TARGET_LANG=c
	@echo "Installing the Miracl library..."
	@sudo $(MAKE) -C build/Miracl MIRACL_TARGET_LANG=c install
	@touch compile-miracl

compile-miracl-cpp:
	@$(MAKE) prepare-miracl MIRACL_DIR=MiraclCPP
	@echo "Compiling the Miracl library (C++)..."
	@$(MAKE) -C build/MiraclCPP MIRACL_TARGET_LANG=cpp
	@echo "Installing the Miracl library..."
	@sudo $(MAKE) -C build/MiraclCPP MIRACL_TARGET_LANG=cpp install
	@touch compile-miracl-cpp

compile-otextension:
	@echo "Compiling the OtExtension library..."
	@cp -r lib/OTExtension build/OTExtension
	@sudo $(MAKE) -C build/OTExtension
	@sudo $(MAKE) -C build/OTExtension install
	@touch compile-otextension

# TODO: add GMP and GF2X
compile-ntl:
	@echo "Compiling the NTL library..."
	@cp -r lib/NTL/unix build/NTL
	@cd build/NTL/src/ && ./configure SHARED=on
	@$(MAKE) -C build/NTL/src/
	@sudo $(MAKE) -C build/NTL/src/ install
	@touch compile-ntl

compile-openssl:
	@echo "Compiling the OpenSSL library..."
	@cp -r lib/OpenSSL build/OpenSSL
	@cd build/OpenSSL && ./config shared -fPIC --openssldir=/usr/local/ssl
	@$(MAKE) -C build/OpenSSL depend
	@$(MAKE) -C build/OpenSSL all
	@sudo $(MAKE) -C build/OpenSSL install
	@touch compile-openssl

$(JAR_BOUNCYCASTLE):
	@echo "Compiling the BouncyCastle library..."
	@cp -r lib/BouncyCastle build/BouncyCastle
	@cd build/BouncyCastle && chmod a+x build15+ && ./build15+
	@mkdir -p build/BouncyCastle/jars/
	@cp build/BouncyCastle/build/artifacts/jdk1.5/jars/bcprov-jdk* build/BouncyCastle/jars/
	@touch compile-bouncycastle
#@sudo apt-get install junit

compile-bouncycastle: $(JAR_BOUNCYCASTLE)

# jni targets
jni-cryptopp: $(JNI_CRYPTOPP)
jni-miracl: $(JNI_MIRACL)
jni-otextension: $(JNI_OTEXTENSION)
jni-ntl: $(JNI_NTL)
jni-openssl: $(JNI_OPENSSL)

# jni real targets
$(JNI_CRYPTOPP): compile-cryptopp
	@echo "Compiling the Crypto++ jni interface..."
	@$(MAKE) -C src/jni/CryptoPPJavaInterface

$(JNI_MIRACL): compile-miracl
	@echo "Compiling the Miracl jni interface..."
	@$(MAKE) -C src/jni/MiraclJavaInterface

$(JNI_OTEXTENSION): compile-miracl-cpp compile-otextension
	@echo "Compiling the OtExtension jni interface..."
	@$(MAKE) -C src/jni/OtExtensionJavaInterface

$(JNI_NTL): compile-ntl
	@echo "Compiling the NTL jni interface..."
	@$(MAKE) -C src/jni/NTLJavaInterface

$(JNI_OPENSSL): compile-openssl
	@echo "Compiling the OpenSSL jni interface..."
	@$(MAKE) -C src/jni/OpenSSLJavaInterface

# clean targets
clean-cryptopp:
	@echo "Cleaning the cryptopp build dir..."
	@rm -rf build/CryptoPP
	@rm -f compile-cryptopp

clean-miracl:
	@echo "Cleaning the miracl build dir..."
	@rm -rf build/Miracl
	@rm -f compile-miracl

clean-miracl-cpp:
	@echo "Cleaning the miracl build dir..."
	@rm -rf build/MiraclCPP
	@rm -f compile-miracl-cpp

clean-otextension:
	@echo "Cleaning the otextension build dir..."
	@rm -rf build/OTExtension
	@rm -f compile-otextension

clean-ntl:
	@echo "Cleaning the ntl build dir..."
	@rm -rf build/NTL
	@rm -f compile-ntl

clean-openssl:
	@echo "Cleaning the openssl build dir..."
	@rm -rf build/OpenSSL
	@rm -f compile-openssl

clean-bouncycastle:
	@echo "Cleaning the bouncycastle build dir..."
	@rm -rf build/BouncyCastle
	@rm -f compile-bouncycastle

prepare-miracl:
	@echo "Copying the miracl source files into the miracl build dir..."
	@mkdir -p build/$(MIRACL_DIR)
	@find lib/Miracl/ -type f -exec cp '{}' build/$(MIRACL_DIR)/ \;
	@rm -f build/$(MIRACL_DIR)/mirdef.h
	@rm -f build/$(MIRACL_DIR)/mrmuldv.c
	@cp -r lib/MiraclCompilation/* build/$(MIRACL_DIR)/

# clean jni
clean-jni-cryptopp:
	@echo "Cleaning the Crypto++ jni build dir..."
	@$(MAKE) -C src/jni/CryptoPPJavaInterface clean

clean-jni-miracl:
	@echo "Cleaning the Miracl jni build dir..."
	@$(MAKE) -C src/jni/MiraclJavaInterface clean

clean-jni-otextension:
	@echo "Cleaning the OtExtension jni build dir..."
	@$(MAKE) -C src/jni/OtExtensionJavaInterface clean

clean-jni-ntl:
	@echo "Cleaning the NTL jni build dir..."
	@$(MAKE) -C src/jni/NTLJavaInterface clean

clean-jni-openssl:
	@echo "Cleaning the OpenSSL jni build dir..."
	@$(MAKE) -C src/jni/OpenSSLJavaInterface clean

clean-libraries: $(CLEAN_TARGETS)
clean-jnis: $(CLEAN_JNI_TARGETS)
clean: clean-libraries clean-jnis
