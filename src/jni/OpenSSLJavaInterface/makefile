# this makefile should be activated using the main scapi makefile:
# > cd [SCAPI_ROOT]
# > make jni-openssl

# compilation options
CXX=g++
CXXFLAGS=-fPIC

# linking options, we prefer our generated shared object will be self-contained.
INCLUDE_ARCHIVES_START = -Wl,-whole-archive
INCLUDE_ARCHIVES_END = -Wl,-no-whole-archive -Wl,--no-undefined

# openssl dependency
OPENSSL_INCLUDES = -I/usr/local/ssl/include/
OPENSSL_LIB_DIR = -L/usr/local/ssl/lib/
OPENSSL_LIB = -lssl -lcrypto

SOURCES = AES.cpp DlogEC.cpp DlogF2m.cpp DlogFp.cpp DlogZp.cpp DSA.cpp F2mPoint.cpp \
	FpPoint.cpp Hash.cpp Hmac.cpp PrpAbs.cpp RC4.cpp RSAOaep.cpp RSAPermutation.cpp \
	RSAPss.cpp SymEncryption.cpp TripleDES.cpp ZpElement.cpp
OBJ_FILES = $(SOURCES:.cpp=.o)

## targets ##

# main target - linking individual *.o files
libOpenSSLJavaInterface.so: $(OBJ_FILES)
	$(CXX) -shared -o $@ $(OBJ_FILES) $(JAVA_INCLUDES) $(OPENSSL_INCLUDES) \
	$(OPENSSL_LIB_DIR) $(INCLUDE_ARCHIVES_START) $(OPENSSL_LIB) $(INCLUDE_ARCHIVES_END)

# each source file is compiled seperately before linking
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< $(OPENSSL_INCLUDES) $(JAVA_INCLUDES)

clean:
	rm -f *~
	rm -f *.o
	rm -f *.so

