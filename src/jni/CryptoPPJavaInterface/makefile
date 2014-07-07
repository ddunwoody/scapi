# this makefile should be activated using the main scapi makefile:
# > cd [SCAPI_ROOT]
# > make jni-cryptopp

# compilation options
CXX=g++
CXXFLAGS=-fPIC

# crypto++ dependency
CRYPTOPP_INCLUDES = -I/usr/include/cryptopp/
CRYPTOPP_LIB = -lcryptopp

# java jvm dependency
# JAVA_HOME and JAVA_INCLUDES must be exported on the parent makefile

SOURCES = AESPermutation.cpp CollisionResistantHash.cpp Examples.cpp DlogElement.cpp \
	DlogGroup.cpp RSAOaep.cpp RSAPermutation.cpp RSAPss.cpp RabinPermutation.cpp \
	TPElement.cpp Utils.cpp
OBJ_FILES = $(SOURCES:.cpp=.o)

## targets ##

# main target - linking individual *.o files
libCryptoPPJavaInterface.so: $(OBJ_FILES)
	$(CXX) -shared -o $@ $(OBJ_FILES) $(JAVA_INCLUDES) $(CRYPTOPP_INCLUDES) $(CRYPTOPP_LIB)

# each source file is compiled seperately before linking
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< $(CRYPTOPP_INCLUDES) $(JAVA_INCLUDES)

clean:
	rm -f *~
	rm -f *.o
	rm -f *.so

