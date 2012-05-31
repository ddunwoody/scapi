#ifndef UTILS_H
#define UTILS_H

#include "stdafx.h"
#include "jni.h" 
#include "cryptlib.h"

using namespace CryptoPP;

class Utils {

public:

	Utils();
	Integer jbyteArrayToCryptoPPInteger (JNIEnv *env, jbyteArray byteArrToConvert);
	Integer* jbyteArrayToCryptoPPIntegerPointer (JNIEnv *env, jbyteArray byteArrToConvert);
	Integer* getPointerToInteger (Integer integerToPointer);
	jbyteArray CryptoPPIntegerTojbyteArray (JNIEnv *env, Integer integerToConvert);
	void extendedEuclideanAlg(Integer a, Integer b, Integer & gcd, Integer & x, Integer&  y);
	Integer SquareRoot(Integer value, Integer mod, Integer p, Integer q, bool check);
	bool HasSquareRoot(Integer value, Integer p, Integer q);
};


#endif
