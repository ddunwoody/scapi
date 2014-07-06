CC = g++ -g #-Wall
CRYPTOPP_INCLUDES = -I/usr/include/cryptopp/
CRYPTOPP_LIB = -lcryptopp
JAVA_INCLUDES = -I/usr/lib/jvm/java-7-openjdk-amd64/include/

CryptoPPJavaInterface.so: AESPermutation.o CollisionResistantHash.o Examples.o \
	DlogElement.o DlogGroup.o RSAOaep.o RSAPermutation.o RSAPss.o \
	RabinPermutation.o TPElement.o Utils.o
	$(CC) -shared -o libCryptoPPJavaInterface.so \
	AESPermutation.o CollisionResistantHash.o Examples.o \
	DlogElement.o DlogGroup.o RSAOaep.o RSAPermutation.o RSAPss.o \
	RabinPermutation.o TPElement.o Utils.o \
	$(CRYPTOPP_INCLUDES) $(JAVA_INCLUDES) $(CRYPTOPP_LIB)

AESPermutation.o:
	$(CC) -fpic -c AESPermutation.cpp $(CRYPTOPP_INCLUDES) $(JAVA_INCLUDES)

CollisionResistantHash.o:
	$(CC) -fpic -c CollisionResistantHash.cpp $(CRYPTOPP_INCLUDES) $(JAVA_INCLUDES)

Examples.o:
	$(CC) -fpic -c Examples.cpp $(CRYPTOPP_INCLUDES) $(JAVA_INCLUDES)

DlogElement.o: Utils.o
	$(CC) -fpic -c DlogElement.cpp $(CRYPTOPP_INCLUDES) $(JAVA_INCLUDES)

DlogGroup.o: Utils.o
	$(CC) -fpic -c DlogGroup.cpp $(CRYPTOPP_INCLUDES) $(JAVA_INCLUDES)

RSAOaep.o: Utils.o
	$(CC) -fpic -c RSAOaep.cpp $(CRYPTOPP_INCLUDES) $(JAVA_INCLUDES)

RSAPermutation.o: Utils.o
	$(CC) -fpic -c RSAPermutation.cpp $(CRYPTOPP_INCLUDES) $(JAVA_INCLUDES)

RSAPss.o: Utils.o
	$(CC) -fpic -c RSAPss.cpp $(CRYPTOPP_INCLUDES) $(JAVA_INCLUDES)

RabinPermutation.o: Utils.o
	$(CC) -fpic -c RabinPermutation.cpp $(CRYPTOPP_INCLUDES) $(JAVA_INCLUDES)

TPElement.o: Utils.o
	$(CC) -fpic -c TPElement.cpp $(CRYPTOPP_INCLUDES) $(JAVA_INCLUDES)

Utils.o:
	$(CC) -fpic -c Utils.cpp $(CRYPTOPP_INCLUDES) $(JAVA_INCLUDES)

clean:
	rm -f *~
	rm -f *.o

