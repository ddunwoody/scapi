# this makefile should be activated using the main scapi makefile:
# > cd [SCAPI_ROOT]
# > make jni-ntl

# compilation options
CXX=g++
CXXFLAGS=-fPIC -fpermissive

# ntl dependency
NTL_INCLUDES = -I$(includedir)
NTL_LIB = -lntl
NTL_LIB_DIR = -L$(libdir)

# sources
SOURCES = EvaluationHashFunction.cpp JniEvaluationHashFunction.cpp SigmaProtocolOR.cpp
OBJ_FILES = $(SOURCES:.cpp=.o)

## targets ##

# main target - linking individual *.o files
libNTLJavaInterface$(JNI_LIB_EXT): $(OBJ_FILES)
	$(CXX) $(SHARED_LIB_OPT) -o $@ $(OBJ_FILES) $(JAVA_INCLUDES) $(NTL_INCLUDES) \
	$(NTL_LIB_DIR) $(INCLUDE_ARCHIVES_START) $(NTL_LIB) $(INCLUDE_ARCHIVES_END)

# each source file is compiled seperately before linking
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< $(NTL_INCLUDES) $(JAVA_INCLUDES)

clean:
	rm -f *~
	rm -f *.o
	rm -f *$(JNI_LIB_EXT)
