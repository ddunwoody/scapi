# detecting a unix os type: could be Linux, Darwin(Mac), FreeBSD, etc...
uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')

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

EXTERNAL_LIBS_TARGETS=compile-cryptopp compile-miracl compile-otextension compile-ntl compile-openssl
JNI_TAGRETS=jni-cryptopp jni-miracl jni-otextension jni-ntl jni-openssl

all: $(JNI_TAGRETS)

# compile and install the crypto++ lib:
# first compile the default target (test program + static lib)
# then also compile the dynamic lib, and finally install.
compile-cryptopp:
	echo "Compiling the Crypto++ library..."
	@$(MAKE) -C lib/CryptoPP CXXFLAGS=$(CXXFLAGS)
	@$(MAKE) -C lib/CryptoPP CXXFLAGS=$(CXXFLAGS) dynamic
	@sudo $(MAKE) -C lib/CryptoPP CXXFLAGS=$(CXXFLAGS) install

compile-miracl:
	echo "Compiling the Miracl library..."

compile-otextension:
	echo "Compiling the OtExtension library..."

compile-ntl:
	echo "Compiling the NTL library..."

compile-openssl:
	echo "Compiling the OpenSSL library..."

jni-cryptopp: compile-cryptopp
	@echo "Compiling the Crypto++ jni interface..."
	@$(MAKE) -C src/jni/CryptoPPJavaInterface

jni-miracl: compile-miracl
	echo "Compiling the Miracl jni interface..."

jni-otextension: compile-otextension
	echo "Compiling the OtExtension jni interface..."

jni-ntl: compile-ntl
	echo "Compiling the NTL jni interface..."

jni-openssl: compile-openssl
	echo "Compiling the OpenSSL jni interface..."
