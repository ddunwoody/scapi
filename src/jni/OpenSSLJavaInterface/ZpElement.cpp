/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2012 - SCAPI (http://crypto.biu.ac.il/scapi)
* This file is part of the SCAPI project.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
* 
* We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to
* http://crypto.biu.ac.il/SCAPI.
* 
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
*/

#include "StdAfx.h"
#include <jni.h>
#include "ZpElement.h"
#include <openssl/bn.h>
#include <iostream>

using namespace std;

/* 
 * function createElement		: Creates the Zp* element.
 * param element				: The bytes of the element that should be built.
 * return						: A pointer to the created element.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_openSSL_OpenSSLZpSafePrimeElement_createElement
  (JNIEnv * env, jobject, jbyteArray element){
	  //Convert the given input into C++ notation.
	  jbyte* el  = (jbyte*) env->GetByteArrayElements(element, 0);

	  //Create a new BIGNUM with the given bytes.
	  BIGNUM *elBN;
	  if(NULL == (elBN = BN_bin2bn((unsigned char*) el, env->GetArrayLength(element), NULL))) {
		  env ->ReleaseByteArrayElements(element, el, 0);
		  return 0;
	  }

	  //Release the allocated memory.
	  env ->ReleaseByteArrayElements(element, el, 0);

	  return (long) elBN;
}

/* 
 * function deleteElement		: Deletes the Zp* element.
 * param zpElement				: A pointer to the element that should be deleted.
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_dlog_openSSL_OpenSSLZpSafePrimeElement_deleteElement
  (JNIEnv *, jobject, jlong zpElement){
	  BN_free((BIGNUM*)zpElement);
}

/* 
 * function getElement		: Returns the bytes value of the given element.
 * param zpElement			: A pointer to an element.
 * return					: The bytes value of the given element.
 */
JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_primitives_dlog_openSSL_OpenSSLZpSafePrimeElement_getElement
  (JNIEnv *env, jobject, jlong zpElement){
	  
	  //Prepare an array to hold the element's bytes.
	  unsigned char* elementBytes = new unsigned char[BN_num_bytes((BIGNUM*)zpElement)];

	  //Convert the element to a char array.
	  int len = BN_bn2bin((BIGNUM*)zpElement, elementBytes);

	   //Build a jbyteArray from the char array.
	  jbyteArray result = env ->NewByteArray(len);
	  env->SetByteArrayRegion(result, 0, len, (jbyte*)elementBytes);

	  //Release the allocated memory.
	  delete elementBytes;
	  return result;
}