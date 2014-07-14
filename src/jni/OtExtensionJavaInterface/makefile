# this makefile should be activated using the main scapi makefile:
# > cd [SCAPI_ROOT]
# > make jni-otextension

# compilation options
CXX=g++
CXXFLAGS=-fPIC

OT_INCLUDES = -I/usr/local/include/OTExtension/
OT_LIB = -lOTExtension

OPENSSL_INCLUDES = -I/usr/local/ssl/include/
OPENSSL_LIB_DIR = -L/usr/local/ssl/lib/
OPENSSL_LIB = -lssl

OtExtensionJavaInterface$(SHARED_LIB_EXT): OtExtension.o
	$(CC) $(SHARED_LIB_OPT) -o libOtExtensionJavaInterface.so OtExtension.o \
	$(OT_INCLUDES) $(JAVA_INCLUDES) $(OT_LIB) $(OPENSSL_INCLUDES) $(OPENSSL_LIB_DIR) $(OPENSSL_LIB)

OtExtension.o:
	$(CC) -fpic -c OtExtension.cpp $(OT_INCLUDES) $(JAVA_INCLUDES) $(OPENSSL_INCLUDES)

clean:
	rm -f *~
	rm -f *.o
	rm -f *$(SHARED_LIB_EXT)
