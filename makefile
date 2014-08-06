# detecting a unix os type: could be Linux, Darwin(Mac), FreeBSD, etc...
uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')
ARCH := $(shell getconf LONG_BIT)

# Prefix for installation (run make prefix=/usr/local to install there instead)
export prefix=$(abspath ./install)
export exec_prefix=$(prefix)
export includedir=$(prefix)/include
export bindir=$(exec_prefix)/bin
export libdir=$(prefix)/lib

export builddir=$(abspath ./build)


# compilation options
CC=gcc
CXX=g++
CFLAGS=-fPIC
CXXFLAGS="-DNDEBUG -g -O2 -fPIC"

ifeq ($(uname_S),Linux)
	JAVA_HOME=$(shell dirname $$(dirname $$(readlink -f `which javac`)))
	JAVA_INCLUDES=-I$(JAVA_HOME)/include/
	CRYPTOPP_CXXFLAGS=$(CXXFLAGS)
	INCLUDE_ARCHIVES_START = -Wl,-whole-archive # linking options, we prefer our generated shared object will be self-contained.
	INCLUDE_ARCHIVES_END = -Wl,-no-whole-archive -Wl,--no-undefined
	SHARED_LIB_OPT:=-shared
	SHARED_LIB_EXT:=.so
	JNI_LIB_EXT:=.so
	OPENSSL_CONFIGURE=./config
	LIBTOOL=libtool
	JNI_PATH=LD_LIBRARY_PATH
endif

ifeq ($(uname_S),Darwin)
	JAVA_HOME=$(shell /usr/libexec/java_home)
	JAVA_INCLUDES=-I$(shell dirname $$(dirname $$(readlink `which javac`)))/Headers/
	CRYPTOPP_CXXFLAGS="-DNDEBUG -g -O2 -fPIC -DCRYPTOPP_DISABLE_ASM -pipe"
	INCLUDE_ARCHIVES_START=-Wl,-all_load
	INCLUDE_ARCHIVES_END=
	SHARED_LIB_OPT:=-dynamiclib
	SHARED_LIB_EXT:=.dylib
	JNI_LIB_EXT:=.jnilib
	OPENSSL_CONFIGURE=./Configure darwin64-x86_64-cc
	LIBTOOL=glibtool
	JNI_PATH=DYLD_LIBRARY_PATH
endif

# export all variables that are used by child makefiles
export JAVA_HOME
export JAVA_INCLUDES
export uname_S
export ARCH
export INCLUDE_ARCHIVES_START
export INCLUDE_ARCHIVES_END
export SHARED_LIB_OPT
export SHARED_LIB_EXT
export JNI_LIB_EXT

# target names
CLEAN_TARGETS:=clean-cryptopp clean-miracl clean-miracl-cpp clean-otextension clean-ntl clean-openssl clean-bouncycastle
CLEAN_JNI_TARGETS:=clean-jni-cryptopp clean-jni-miracl clean-jni-otextension clean-jni-ntl clean-jni-openssl

# target names of jni shared libraries
JNI_CRYPTOPP:=src/jni/CryptoPPJavaInterface/libCryptoPPJavaInterface$(JNI_LIB_EXT)
JNI_MIRACL:=src/jni/MiraclJavaInterface/libMiraclJavaInterface$(JNI_LIB_EXT)
JNI_OTEXTENSION:=src/jni/OtExtensionJavaInterface/libOtExtensionJavaInterface$(JNI_LIB_EXT)
JNI_NTL:=src/jni/NTLJavaInterface/libNTLJavaInterface$(JNI_LIB_EXT)
JNI_OPENSSL:=src/jni/OpenSSLJavaInterface/libOpenSSLJavaInterface$(JNI_LIB_EXT)
JNI_TAGRETS=jni-cryptopp jni-miracl jni-otextension jni-ntl jni-openssl

# basenames of created jars (apache commons, bouncy castle, scapi)
#BASENAME_BOUNCYCASTLE:=bcprov-jdk15on-151b18.jar
BASENAME_BOUNCYCASTLE:=bcprov-jdk15on-150.jar
BASENAME_APACHE_COMMONS:=commons-exec-1.2.jar
BASENAME_JUNIT:=junit-3.7.jar
BASENAME_SCAPI:=Scapi-V2-3-0.jar

# target names of created jars (apache commons, bouncy castle, scapi)
#JAR_BOUNCYCASTLE:=$(builddir)/BouncyCastle/jars/$(BASENAME_BOUNCYCASTLE)
JAR_BOUNCYCASTLE:=assets/$(BASENAME_BOUNCYCASTLE)
JAR_APACHE_COMMONS:=assets/$(BASENAME_APACHE_COMMONS)
JAR_JUNIT:=$(shell pwd)/assets/$(BASENAME_JUNIT)
JAR_SCAPI:=$(builddir)/scapi/$(BASENAME_SCAPI)

# ntl
NTL_CFLAGS="-fPIC -O2"

# scapi install dir
INSTALL_DIR=$(prefix)/scapi

# scripts
SCRIPTS:=scripts/scapi.sh scripts/scapic.sh

# external libs
EXTERNAL_LIBS_TARGETS:=compile-cryptopp compile-miracl compile-otextension compile-ntl compile-openssl

## targets
all: $(JNI_TAGRETS) $(JAR_BOUNCYCASTLE) $(JAR_APACHE_COMMONS) compile-scapi $(SCRIPTS)

# compile and install the crypto++ lib:
# first compile the default target (test program + static lib)
# then also compile the dynamic lib, and finally install.
compile-cryptopp:
	@echo "Compiling the Crypto++ library..."
	@cp -r lib/CryptoPP/ $(builddir)/CryptoPP/
	@$(MAKE) -C $(builddir)/CryptoPP CXX=$(CXX) CXXFLAGS=$(CRYPTOPP_CXXFLAGS)
	@$(MAKE) -C $(builddir)/CryptoPP CXX=$(CXX) CXXFLAGS=$(CRYPTOPP_CXXFLAGS) dynamic
#	@sudo $(MAKE) -C $(builddir)/CryptoPP CXX=$(CXX) CXXFLAGS=$(CRYPTOPP_CXXFLAGS) install
	@touch compile-cryptopp

prepare-miracl:
	@echo "Copying the miracl source files into the miracl build dir..."
	@mkdir -p $(builddir)/$(MIRACL_DIR)
	@find lib/Miracl/ -type f -exec cp '{}' $(builddir)/$(MIRACL_DIR)/ \;
	@rm -f $(builddir)/$(MIRACL_DIR)/mirdef.h
	@rm -f $(builddir)/$(MIRACL_DIR)/mrmuldv.c
	@cp -r lib/MiraclCompilation/* $(builddir)/$(MIRACL_DIR)/
	@ln -s $(builddir)/$(MIRACL_DIR) $(builddir)/$(MIRACL_DIR)/miracl

compile-miracl: 
	@$(MAKE) prepare-miracl MIRACL_DIR=Miracl
	@echo "Compiling the Miracl library (C)..."
	@$(MAKE) -C $(builddir)/Miracl MIRACL_TARGET_LANG=c
	@echo "Installing the Miracl library..."
#	@sudo $(MAKE) -C $(builddir)/Miracl MIRACL_TARGET_LANG=c install
	@touch compile-miracl

compile-miracl-cpp:
	@$(MAKE) prepare-miracl MIRACL_DIR=MiraclCPP
	@echo "Compiling the Miracl library (C++)..."
	@$(MAKE) -C $(builddir)/MiraclCPP MIRACL_TARGET_LANG=cpp
	@echo "Installing the Miracl library..."
#	@sudo $(MAKE) -C $(builddir)/MiraclCPP MIRACL_TARGET_LANG=cpp install
	@touch compile-miracl-cpp

compile-otextension: compile-openssl compile-miracl
	@echo "Compiling the OtExtension library..."
	@cp -r lib/OTExtension $(builddir)/OTExtension
	@$(MAKE) -C $(builddir)/OTExtension
#	@sudo $(MAKE) -C $(builddir)/OTExtension SHARED_LIB_EXT=$(SHARED_LIB_EXT) install
	@touch compile-otextension

# TODO: add GMP and GF2X
compile-ntl:
	@echo "Compiling the NTL library..."
	@cp -r lib/NTL/unix $(builddir)/NTL
	@cd $(builddir)/NTL/src/ && ./configure CFLAGS=$(NTL_CFLAGS)
	@$(MAKE) -C $(builddir)/NTL/src/
#	@sudo $(MAKE) -C $(builddir)/NTL/src/ install
	@ln -s $(builddir)/NTL/src/ntl.a $(builddir)/NTL/src/libntl.a
	@touch compile-ntl

compile-openssl:
	@echo "Compiling the OpenSSL library..."
	@cp -r lib/OpenSSL $(builddir)/OpenSSL
	@cd $(builddir)/OpenSSL && $(OPENSSL_CONFIGURE) shared -fPIC --openssldir=$(prefix)/ssl
	@$(MAKE) -C $(builddir)/OpenSSL depend
	@$(MAKE) -C $(builddir)/OpenSSL all
#	@sudo $(MAKE) -C $(builddir)/OpenSSL install
	@touch compile-openssl

compile-bouncycastle: $(JAR_BOUNCYCASTLE)
compile-scapi: $(JAR_SCAPI)
compile-scripts: $(SCRIPTS)

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
	@cp $@ assets/

$(JNI_MIRACL): compile-miracl
	@echo "Compiling the Miracl jni interface..."
	@$(MAKE) -C src/jni/MiraclJavaInterface
	@cp $@ assets/

$(JNI_OTEXTENSION): compile-miracl-cpp compile-otextension
	@echo "Compiling the OtExtension jni interface..."
	@$(MAKE) -C src/jni/OtExtensionJavaInterface
	@cp $@ assets/

$(JNI_NTL): compile-ntl
	@echo "Compiling the NTL jni interface..."
	@$(MAKE) -C src/jni/NTLJavaInterface
	@cp $@ assets/

$(JNI_OPENSSL): compile-openssl
	@echo "Compiling the OpenSSL jni interface..."
	@$(MAKE) -C src/jni/OpenSSLJavaInterface
	@cp $@ assets/

# TODO: for now we avoid re-compiling bouncy castle, since it is very unstable,
# and it does not compile on MAC OS X correctly.
$(JAR_BOUNCYCASTLE):
#@echo "Compiling the BouncyCastle library..."
#@cp -r lib/BouncyCastle $(builddir)/BouncyCastle
#cd $(builddir)/BouncyCastle && export JAVA_HOME=$(JAVA_HOME) && export ANT_HOME=$(ANT_HOME) && ant -f ant/jdk15+.xml build
#cd $(builddir)/BouncyCastle && export JAVA_HOME=$(JAVA_HOME) && export ANT_HOME=$(ANT_HOME) && ant -f ant/jdk15+.xml zip-src
#@cp $(builddir)/BouncyCastle/build/artifacts/jdk1.5/jars/bcprov-jdk* assets/
#@touch compile-bouncycastle

$(JAR_SCAPI): $(JAR_BOUNCYCASTLE) $(JAR_APACHE_COMMONS)
	@echo "Compiling the SCAPI java code..."
	@ant
	@cp $@ assets/

scripts/scapi.sh: scripts/scapi.sh.tmpl
	sed -e "s;%SCAPIDIR%;$(INSTALL_DIR);g" -e "s;%APACHECOMMONS%;$(BASENAME_APACHE_COMMONS);g" \
	-e "s;%SCAPI%;$(BASENAME_SCAPI);g" -e "s;%BOUNCYCASTLE%;$(BASENAME_BOUNCYCASTLE);g" \
	-e "s;%JNIPATH%;$(JNI_PATH);g" $< > $@

scripts/scapic.sh: scripts/scapic.sh.tmpl
	sed -e "s;%SCAPIDIR%;$(INSTALL_DIR);g" -e "s;%APACHECOMMONS%;$(BASENAME_APACHE_COMMONS);g" \
	-e "s;%SCAPI%;$(BASENAME_SCAPI);g" -e "s;%BOUNCYCASTLE%;$(BASENAME_BOUNCYCASTLE);g" $< > $@

install: all
	@echo "Installing SCAPI..."
	install -d $(INSTALL_DIR)
	install -m 0644 assets/*$(JNI_LIB_EXT) $(INSTALL_DIR)
	install -m 0644 assets/*.jar $(INSTALL_DIR)
	install -d ./install/usr/bin
	install -m 0755 scripts/scapi.sh ./install/usr/bin/scapi
	install -m 0755 scripts/scapic.sh ./install/usr/bin/scapic
	@echo "Done."

# clean targets
clean-cryptopp:
	@echo "Cleaning the cryptopp build dir..."
	@rm -rf $(builddir)/CryptoPP
	@rm -f compile-cryptopp

clean-miracl:
	@echo "Cleaning the miracl build dir..."
	@rm -rf $(builddir)/Miracl
	@rm -f compile-miracl

clean-miracl-cpp:
	@echo "Cleaning the miracl build dir..."
	@rm -rf $(builddir)/MiraclCPP
	@rm -f compile-miracl-cpp

clean-otextension:
	@echo "Cleaning the otextension build dir..."
	@rm -rf $(builddir)/OTExtension
	@rm -f compile-otextension

clean-ntl:
	@echo "Cleaning the ntl build dir..."
	@rm -rf $(builddir)/NTL
	@rm -f compile-ntl

clean-openssl:
	@echo "Cleaning the openssl build dir..."
	@rm -rf $(builddir)/OpenSSL
	@rm -f compile-openssl

clean-bouncycastle:
	@echo "Cleaning the bouncycastle build dir..."
	@rm -rf $(builddir)/BouncyCastle
	@rm -f compile-bouncycastle

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
clean-scripts:
	@echo "cleaning the SCAPI shell scripts"
	@rm -f scripts/*.sh

clean: clean-libraries clean-jnis clean-scripts
