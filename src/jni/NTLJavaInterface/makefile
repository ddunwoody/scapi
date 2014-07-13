# this makefile should be activated using the main scapi makefile:
# > cd [SCAPI_ROOT]
# > make jni-ntl

# compilation options
CXX=g++
CXXFLAGS=-fPIC

# linking options, we prefer our generated shared object will be self-contained.
INCLUDE_ARCHIVES_START = -Wl,-whole-archive
INCLUDE_ARCHIVES_END = -Wl,-no-whole-archive -Wl,--no-undefined

# ntl dependency
NTL_INCLUDES = -I/usr/local/include/NTL/
NTL_LIB = -lntl
NTL_LIB_DIR = -L/usr/local/lib/

# sources
SOURCES = EvaluationHashFunction.cpp JniEvaluationHashFunction.cpp SigmaProtocolOR.cpp
OBJ_FILES = $(SOURCES:.cpp=.o)

## targets ##

# main target - linking individual *.o files
libNTLJavaInterface.so: $(OBJ_FILES)
	$(CXX) -shared -o $@ $(OBJ_FILES) $(JAVA_INCLUDES) $(NTL_INCLUDES) \
	$(NTL_LIB_DIR) $(INCLUDE_ARCHIVES_START) $(NTL_LIB) $(INCLUDE_ARCHIVES_END)

# each source file is compiled seperately before linking
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< $(NTL_INCLUDES) $(JAVA_INCLUDES)

clean:
	rm -f *~
	rm -f *.o
	rm -f *.so
