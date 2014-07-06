CC = g++ -g #-Wall
OPENSSL_INCLUDES = -I/usr/local/ssl/include/
OPENSSL_LIB_DIR = -L/usr/local/ssl/lib/
OPENSSL_LIB = -lssl
JAVA_INCLUDES = -I/usr/lib/jvm/java-7-openjdk-amd64/include/

OpenSSLJavaInterface.so: AES.o DlogEC.o DlogF2m.o DlogFp.o DlogZp.o DSA.o F2mPoint.o \
	FpPoint.o Hash.o Hmac.o PrpAbs.o RC4.o RSAOaep.o RSAPermutation.o RSAPss.o \
	SymEncryption.o TripleDES.o ZpElement.o
	$(CC) -shared -o libOpenSSLJavaInterface.so \
	AES.o DlogEC.o DlogF2m.o DlogFp.o DlogZp.o DSA.o F2mPoint.o FpPoint.o \
	Hash.o Hmac.o PrpAbs.o RC4.o RSAOaep.o RSAPermutation.o RSAPss.o \
	SymEncryption.o TripleDES.o ZpElement.o \
	$(OPENSSL_INCLUDES) $(JAVA_INCLUDES) $(OPENSSL_LIB_DIR) $(OPENSSL_LIB)

AES.o:
	$(CC) -fpic -c AES.cpp $(OPENSSL_INCLUDES) $(JAVA_INCLUDES)
DlogEC.o:
	$(CC) -fpic -c DlogEC.cpp $(OPENSSL_INCLUDES) $(JAVA_INCLUDES)
DlogF2m.o: DlogEC.o
	$(CC) -fpic -c DlogF2m.cpp $(OPENSSL_INCLUDES) $(JAVA_INCLUDES)
DlogFp.o: DlogEC.o
	$(CC) -fpic -c DlogFp.cpp $(OPENSSL_INCLUDES) $(JAVA_INCLUDES)
DlogZp.o:
	$(CC) -fpic -c DlogZp.cpp $(OPENSSL_INCLUDES) $(JAVA_INCLUDES)
DSA.o:
	$(CC) -fpic -c DSA.cpp $(OPENSSL_INCLUDES) $(JAVA_INCLUDES)
F2mPoint.o: DlogEC.o
	$(CC) -fpic -c F2mPoint.cpp $(OPENSSL_INCLUDES) $(JAVA_INCLUDES)
FpPoint.o: DlogEC.o
	$(CC) -fpic -c FpPoint.cpp $(OPENSSL_INCLUDES) $(JAVA_INCLUDES)
Hash.o:
	$(CC) -fpic -c Hash.cpp $(OPENSSL_INCLUDES) $(JAVA_INCLUDES)
Hmac.o:
	$(CC) -fpic -c Hmac.cpp $(OPENSSL_INCLUDES) $(JAVA_INCLUDES)
PrpAbs.o:
	$(CC) -fpic -c PrpAbs.cpp $(OPENSSL_INCLUDES) $(JAVA_INCLUDES)
RC4.o:
	$(CC) -fpic -c RC4.cpp $(OPENSSL_INCLUDES) $(JAVA_INCLUDES)
RSAOaep.o:
	$(CC) -fpic -c RSAOaep.cpp $(OPENSSL_INCLUDES) $(JAVA_INCLUDES)
RSAPermutation.o:
	$(CC) -fpic -c RSAPermutation.cpp $(OPENSSL_INCLUDES) $(JAVA_INCLUDES)
RSAPss.o:
	$(CC) -fpic -c RSAPss.cpp $(OPENSSL_INCLUDES) $(JAVA_INCLUDES)
SymEncryption.o:
	$(CC) -fpic -c SymEncryption.cpp $(OPENSSL_INCLUDES) $(JAVA_INCLUDES)
TripleDES.o:
	$(CC) -fpic -c TripleDES.cpp $(OPENSSL_INCLUDES) $(JAVA_INCLUDES)
ZpElement.o:
	$(CC) -fpic -c ZpElement.cpp $(OPENSSL_INCLUDES) $(JAVA_INCLUDES)

clean:
	rm -f *~
	rm -f *.o

