CC = g++ -g #-Wall
FPIC = -fPIC
NTL_INCLUDES = -I/usr/local/include/NTL/
NTL_LIB = -lntl
JAVA_INCLUDES = -I/usr/lib/jvm/java-7-openjdk-amd64/include/

NTLJavaInterface.so: EvaluationHashFunction.o JniEvaluationHashFunction.o SigmaProtocolOR.o
	$(CC) -shared -o libNTLJavaInterface.so \
	EvaluationHashFunction.o JniEvaluationHashFunction.o SigmaProtocolOR.o \
	$(NTL_INCLUDES) $(JAVA_INCLUDES) $(NTL_LIB_DIR) $(NTL_LIB)

EvaluationHashFunction.o:
	$(CC) $(FPIC) -c EvaluationHashFunction.cpp $(NTL_INCLUDES) $(JAVA_INCLUDES)
JniEvaluationHashFunction.o: EvaluationHashFunction.o
	$(CC) $(FPIC) -c JniEvaluationHashFunction.cpp $(NTL_INCLUDES) $(JAVA_INCLUDES)
SigmaProtocolOR.o: EvaluationHashFunction.o
	$(CC) $(FPIC) -c SigmaProtocolOR.cpp $(NTL_INCLUDES) $(JAVA_INCLUDES)

clean:
	rm -f *~
	rm -f *.o
