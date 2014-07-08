# this makefile should be activated using the main scapi makefile:
# > cd [SCAPI_ROOT]
# > make jni-miracl

# compilation options
CXX=g++
CXXFLAGS=-fPIC

# linking options, we prefer our generated shared object will be self-contained.
INCLUDE_ARCHIVES_START = -Wl,-whole-archive
INCLUDE_ARCHIVES_END = -Wl,-no-whole-archive -Wl,--no-undefined

# miracl dependency
MIRACL_INCLUDES = -I/usr/local/include/miracl/
MIRACL_LIB = -lmiracl

SOURCES = Utils.c Dlog.c ECF2mPoint.c ECFpPoint.c
CPP_SOURCES = AESPermutation.cpp

OBJ_FILES = $(SOURCES:.c=.o)
CPP_OBJ_FILES = $(CPP_SOURCES:.cpp=.opp)

## targets ##

# main target - linking individual *.o files
libMiraclJavaInterface.so: $(OBJ_FILES)
	$(CXX) -shared -o $@ $(OBJ_FILES) $(MIRACL_INCLUDES) $(JAVA_INCLUDES) \
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
	rm -f *.so
