# this makefile should be activated using the main scapi makefile:
# > cd [SCAPI_ROOT]
# > make jni-miracl

INCLUDE_ARCHIVES_START = -Wl,-whole-archive
INCLUDE_ARCHIVES_END = -Wl,-no-whole-archive -Wl,--no-undefined

# compilation options
CXX=g++
CXXFLAGS=-fPIC

# miracl dependency
MIRACL_INCLUDES = -I/usr/local/include/miracl/
MIRACL_LIB = -lmiracl

SOURCES = AESPermutation.cpp Utils.cpp DLog.cpp ECF2mPoint.cpp ECFpPoint.cpp
OBJ_FILES = $(SOURCES:.cpp=.o)

## targets ##

# main target - linking individual *.o files
libMiraclJavaInterface.so: $(OBJ_FILES)
	$(CXX) -shared -o $@ $(OBJ_FILES) $(MIRACL_INCLUDES) $(JAVA_INCLUDES) \
	$(INCLUDE_ARCHIVES_START) $(MIRACL_LIB) $(INCLUDE_ARCHIVES_END)

# each source file is compiled seperately before linking
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< $(MIRACL_INCLUDES) $(JAVA_INCLUDES)

clean:
	rm -f *~
	rm -f *.o
	rm -f *.so
