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
#include "AES.h"
#include <openssl/evp.h>
#include <iostream>

using namespace std;

/* 
 * function createAESCompute : This function creates an AES object that computes the AES permutation
 * return					 : a pointer to the created object.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_prf_openSSL_OpenSSLAES_createAESCompute
  (JNIEnv *, jobject){
	  
	  //Create a new cipher.
	  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	  
	  return (long) ctx;
}

/* 
 * function createAESInvert : This function creates an AES object that inverts the AES permutation
 * return					: a pointer to the created object.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_prf_openSSL_OpenSSLAES_createAESInvert
  (JNIEnv *, jobject){
	  
	  //Create a new cipher.
	  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	  
	  return (long) ctx;
}

/* 
 * function setKey			: Sets both aesCompute and AESInvert objects with the given key.
 * param aesCompute			: pointer to the AES object that compute the prmutation.
 * param aesInvert			: pointer to the AES object that invert the prmutation.
 * param key				: the key to set.
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_prf_openSSL_OpenSSLAES_setKey
  (JNIEnv *env, jobject, jlong aesCompute, jlong aesInvert, jbyteArray key){
	  //Convert the given data into c++ notation.
	  jbyte* keyBytes  = (jbyte*) env->GetByteArrayElements(key, 0);
	
	  int len = env->GetArrayLength(key)*8; //number of bit in key.

	  //Create the requested block cipher.
	  const EVP_CIPHER* cipher;
	  switch(len)  {
		case 128: cipher = EVP_aes_128_ecb();
						   break;
		case 192: cipher = EVP_aes_192_ecb();
						   break;
		case 256: cipher = EVP_aes_256_ecb();
						   break;
		default: break;
	  }
	  
	  //Initialize the AES objects with the key.
	  EVP_EncryptInit ((EVP_CIPHER_CTX *)aesCompute, cipher, (unsigned char*)keyBytes, NULL);
	  EVP_DecryptInit ((EVP_CIPHER_CTX *)aesInvert, cipher, (unsigned char*)keyBytes, NULL);
	  
	  //Set the AES objects with NO PADDING.
	  EVP_CIPHER_CTX_set_padding((EVP_CIPHER_CTX *)aesCompute, 0);
	  EVP_CIPHER_CTX_set_padding((EVP_CIPHER_CTX *)aesInvert, 0);

	  //Release the allocated memory.
	  env->ReleaseByteArrayElements(key, keyBytes, 0);
	  
}
