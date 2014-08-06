# this makefile should be activated using the main scapi makefile:
# > cd [SCAPI_ROOT]
# > make jni-miracl

# compilation options
CXX=g++
CXXFLAGS=-fPIC

# miracl dependency
MIRACL_INCLUDES = -I$(includedir)/miracl
MIRACL_LIB = -L$(libdir) -lmiracl

SOURCES = Utils.c Dlog.c ECF2mPoint.c ECFpPoint.c
CPP_SOURCES = AESPermutation.cpp

OBJ_FILES = $(SOURCES:.c=.o)
CPP_OBJ_FILES = $(CPP_SOURCES:.cpp=.opp)

## targets ##

# main target - linking individual *.o files
libMiraclJavaInterface$(JNI_LIB_EXT): $(OBJ_FILES)
	$(CXX) $(SHARED_LIB_OPT) -o $@ $(OBJ_FILES) $(MIRACL_INCLUDES) $(JAVA_INCLUDES) \
	$(INCLUDE_ARCHIVES_START) $(MIRACL_LIB) $(INCLUDE_ARCHIVES_END)

# each source file is compiled seperately before linking
%.o: %.c
	$(CXX) $(CXXFLAGS) -c $< $(MIRACL_INCLUDES) $(JAVA_INCLUDES)

%.opp: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@ $(MIRACL_INCLUDES) $(JAVA_INCLUDES)

clean:
	rm -f *~
	rm -f *.o
	rm -f *.opp
	rm -f *$(JNI_LIB_EXT)
