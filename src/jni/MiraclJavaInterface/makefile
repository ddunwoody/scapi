CC = g++ -g #-Wall
MIRACL_INCLUDES = -I/usr/local/include/miracl/
INCLUDE_ARCHIVES_START = -Wl,-whole-archive
INCLUDE_ARCHIVES_END = -Wl,-no-whole-archive -Wl,--no-undefined
MIRACL_LIB = -lmiracl
JAVA_INCLUDES = -I/usr/lib/jvm/java-7-openjdk-amd64/include/

MiraclJavaInterface.so: AESPermutation.o Utils.o DLog.o ECF2mPoint.o ECFpPoint.o
	$(CC) -shared -o libMiraclJavaInterface.so \
	AESPermutation.o  Utils.o DLog.o ECF2mPoint.o ECFpPoint.o \
	$(MIRACL_INCLUDES) $(JAVA_INCLUDES) $(INCLUDE_ARCHIVES_START) $(MIRACL_LIB) $(INCLUDE_ARCHIVES_END)

AESPermutation.o:
	$(CC) -fpic -c AESPermutation.cpp $(MIRACL_INCLUDES) $(JAVA_INCLUDES)

DLog.o: Utils.o
	$(CC) -fpic -c DLog.c $(MIRACL_INCLUDES) $(JAVA_INCLUDES)

ECF2mPoint.o: Utils.o
	$(CC) -fpic -c ECF2mPoint.c $(MIRACL_INCLUDES) $(JAVA_INCLUDES)

ECFpPoint.o: Utils.o
	$(CC) -fpic -c ECFpPoint.c $(MIRACL_INCLUDES) $(JAVA_INCLUDES)

Utils.o:
	$(CC) -fpic -c Utils.c $(MIRACL_INCLUDES) $(JAVA_INCLUDES)

clean:
	rm -f *~
	rm -f *.o
	rm -f *.so
