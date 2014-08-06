# this makefile should be activated using the main scapi makefile:
# > cd [SCAPI_ROOT]
# > make jni-cryptopp

# compilation options
CXX=g++
CXXFLAGS=-fPIC

# crypto++ dependency
CRYPTOPP_INCLUDES = -I$(includedir)/cryptopp/
CRYPTOPP_LIB = -L$(libdir) -lcryptopp

# java jvm dependency
# JAVA_HOME and JAVA_INCLUDES must be exported on the parent makefile

SOURCES = AESPermutation.cpp CollisionResistantHash.cpp Examples.cpp DlogElement.cpp \
	DlogGroup.cpp RSAOaep.cpp RSAPermutation.cpp RSAPss.cpp RabinPermutation.cpp \
	TPElement.cpp Utils.cpp
OBJ_FILES = $(SOURCES:.cpp=.o)

## targets ##

# main target - linking individual *.o files
libCryptoPPJavaInterface$(JNI_LIB_EXT): $(OBJ_FILES)
	$(CXX) $(SHARED_LIB_OPT) -o $@ $(OBJ_FILES) $(JAVA_INCLUDES) $(CRYPTOPP_INCLUDES) \
	$(INCLUDE_ARCHIVES_START) $(CRYPTOPP_LIB) $(INCLUDE_ARCHIVES_END)

# each source file is compiled seperately before linking
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< $(CRYPTOPP_INCLUDES) $(JAVA_INCLUDES)

clean:
	rm -f *~
	rm -f *.o
	rm -f *$(JNI_LIB_EXT)

