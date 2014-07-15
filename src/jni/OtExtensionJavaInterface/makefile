# this makefile should be activated using the main scapi makefile:
# > cd [SCAPI_ROOT]
# > make jni-otextension

# compilation options
CXX=g++
CXXFLAGS=-fPIC

# OTExtension dependency
OT_INCLUDES = -I/usr/local/include/OTExtension/
OT_LIB = -lOTExtension

# OPENSSL dependency
OPENSSL_INCLUDES = -I/usr/local/ssl/include/
OPENSSL_LIB_DIR = -L/usr/local/ssl/lib/
OPENSSL_LIB = -lssl -lcrypto

## targets ##

# main target - linking individual *.o files
libOtExtensionJavaInterface$(JNI_LIB_EXT): OtExtension.o
	$(CXX) $(SHARED_LIB_OPT) -o $@ $< $(OT_INCLUDES) $(JAVA_INCLUDES) \
	$(OPENSSL_INCLUDES) $(OPENSSL_LIB_DIR) \
	$(INCLUDE_ARCHIVES_START) $(OPENSSL_LIB) $(OT_LIB) $(INCLUDE_ARCHIVES_END)

OtExtension.o: OtExtension.cpp
	$(CXX) -fpic -c $< $(OT_INCLUDES) $(JAVA_INCLUDES) $(OPENSSL_INCLUDES)

clean:
	rm -f *~
	rm -f *.o
	rm -f *$(JNI_LIB_EXT)
