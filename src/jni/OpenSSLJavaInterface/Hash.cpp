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
#include "Hash.h"
#include <openssl/evp.h>
#include <iostream>

using namespace std;

/* 
 * function createHash		: Create a native hash function.
 * param hashName			: The name of the requested hash.
 * return					: Pointer to the created hash.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_hash_openSSL_OpenSSLHash_createHash
  (JNIEnv * env, jobject, jstring hashName){

	  EVP_MD_CTX* mdctx;
	  const EVP_MD *md;

	  OpenSSL_add_all_digests();
 
	  //Get the string from java.
	  const char* name = env->GetStringUTFChars(hashName, NULL);

	  //Get the OpenSSL digest.
	  md = EVP_get_digestbyname(name);
	  if(md == 0) {
		  env->ReleaseStringUTFChars(hashName, name);
          return 0;
	  }
	  env->ReleaseStringUTFChars(hashName, name);
	
	  //Create an OpenSSL EVP_MD_CTX struct and initialize it with the created hash.
	  mdctx = EVP_MD_CTX_create();
	  if (0 == (EVP_DigestInit(mdctx, md))) return 0;
	  

	  return (long) mdctx;
}

/* 
 * function algName		: Returns the hash name.
 * param hash			: Pointer to the native hash.
 * return				: The name of the hash, as OpenSSL calls it.
 */
JNIEXPORT jstring JNICALL Java_edu_biu_scapi_primitives_hash_openSSL_OpenSSLHash_algName
  (JNIEnv *env, jobject, jlong hash){
	  int type = EVP_MD_CTX_type((EVP_MD_CTX *) hash);
	  const char* name = OBJ_nid2sn(type);
	  
	  //Return a string that Java can understand with the name of the algorithm.
	  return env->NewStringUTF(name);
	 
}

/* 
 * function updateHash	: Update the hash function with the given message.
 * param hash			: Pointer to the native hash.
 * param message		: The message to update the hash with.
 * param len			: The length of the message.
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_hash_openSSL_OpenSSLHash_updateHash
  (JNIEnv *env, jobject, jlong hash, jbyteArray message, jlong len){
	  //convert the message to c++ notation.
	  jbyte* msg = env->GetByteArrayElements(message, 0);

	  //Update the hash with the message.
	  EVP_DigestUpdate((EVP_MD_CTX *) hash, msg, len);

	  env->ReleaseByteArrayElements(message, msg, 0);
}

/* 
 * function finalHash	: Finalize the hash function.
 * param result			: Array to hold the hashed message.
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_hash_openSSL_OpenSSLHash_finalHash
  (JNIEnv *env, jobject, jlong hash, jbyteArray result){
	  //Get the size of the hashed message.
	  int size = EVP_MD_CTX_size((EVP_MD_CTX *)hash);
	  
	  //Allocate a new byte array with the size of the specific hash algorithm.
	  unsigned char* ret = new unsigned char[size]; 

	  //Compute the hash function and put the result in ret.
	  EVP_DigestFinal_ex((EVP_MD_CTX *)hash, ret, NULL);
	  
	  //Initialize the hash structure again to enable repeated calls.
	  EVP_DigestInit((EVP_MD_CTX *)hash, EVP_MD_CTX_md((EVP_MD_CTX *)hash));
	  
	  //Put the result of the final computation in the output array passed from java.
	  env->SetByteArrayRegion(result, 0, size, (jbyte*)((char*)ret)); 
	  
	  //Make sure to release the dynamically allocated memory. Will not be deleted by the JVM.
	  delete ret;
}

/* 
 * function getDigestSize	: Returns the length of the hashed message.
 */
JNIEXPORT jint JNICALL Java_edu_biu_scapi_primitives_hash_openSSL_OpenSSLHash_getDigestSize
  (JNIEnv *, jobject, jlong hash){
	  
	  //Get the size of the hashed message.
	  return EVP_MD_CTX_size((EVP_MD_CTX *)hash);
}

/* 
 * function deleteHash	: Deletes the hash structure.
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_hash_openSSL_OpenSSLHash_deleteHash
  (JNIEnv *, jobject, jlong hash){
	  EVP_MD_CTX_destroy((EVP_MD_CTX *)hash);
}