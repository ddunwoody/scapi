CC = g++ -g #-Wall
OT_INCLUDES = -I/usr/local/include/OtExtension/
OT_LIB = -lOtExtension
OPENSSL_INCLUDES = -I/usr/local/ssl/include/
OPENSSL_LIB_DIR = -L/usr/local/ssl/lib/
OPENSSL_LIB = -lssl
JAVA_INCLUDES = -I/usr/lib/jvm/java-7-openjdk-amd64/include/

OtExtensionJavaInterface.so: OtExtension.o
	$(CC) -shared -o libOtExtensionJavaInterface.so OtExtension.o \
	$(OT_INCLUDES) $(JAVA_INCLUDES) $(OT_LIB) $(OPENSSL_INCLUDES) $(OPENSSL_LIB_DIR) $(OPENSSL_LIB)

OtExtension.o:
	$(CC) -fpic -c OtExtension.cpp $(OT_INCLUDES) $(JAVA_INCLUDES) $(OPENSSL_INCLUDES)

clean:
	rm -f *~
	rm -f *.o

