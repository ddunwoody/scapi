# this makefile should be activated using the main scapi makefile:
# > cd [SCAPI_ROOT]
# > make jni-openssl

# compilation options
CXX=g++
CXXFLAGS=-fPIC

# openssl dependency
OPENSSL_INCLUDES = -I$(prefix)/ssl/include
OPENSSL_LIB_DIR = -L$(prefix)/ssl/lib
OPENSSL_LIB = -lssl -lcrypto

SOURCES = AES.cpp DlogEC.cpp DlogF2m.cpp DlogFp.cpp DlogZp.cpp DSA.cpp F2mPoint.cpp \
	FpPoint.cpp Hash.cpp Hmac.cpp PrpAbs.cpp RC4.cpp RSAOaep.cpp RSAPermutation.cpp \
	RSAPss.cpp SymEncryption.cpp TripleDES.cpp ZpElement.cpp
OBJ_FILES = $(SOURCES:.cpp=.o)

## targets ##

# main target - linking individual *.o files
libOpenSSLJavaInterface$(JNI_LIB_EXT): $(OBJ_FILES)
	$(CXX) $(SHARED_LIB_OPT) -o $@ $(OBJ_FILES) $(JAVA_INCLUDES) $(OPENSSL_INCLUDES) \
	$(OPENSSL_LIB_DIR) $(INCLUDE_ARCHIVES_START) $(OPENSSL_LIB) $(INCLUDE_ARCHIVES_END)

# each source file is compiled seperately before linking
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< $(OPENSSL_INCLUDES) $(JAVA_INCLUDES)

clean:
	rm -f *~
	rm -f *.o
	rm -f *$(JNI_LIB_EXT)

