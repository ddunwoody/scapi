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
#include "Hmac.h"
#include <openssl/hmac.h>
#include <iostream>

using namespace std;

/* 
 * function createHMAC		: Create a native hmac object.
 * param hashName			: The name of the underlying hash to use.
 * return					: Pointer to the created hmac.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_prf_openSSL_OpenSSLHMAC_createHMAC
  (JNIEnv *env, jobject, jstring hashName){
	  HMAC_CTX *ctx = new  HMAC_CTX;

	  OpenSSL_add_all_digests();
	  
	  //get the hash name from java.
	  const char* name = env->GetStringUTFChars(hashName, NULL);
	  //Get the underlying hash function.
	  const EVP_MD *md = EVP_get_digestbyname(name);

	  //Release the allocated memory.
	  env->ReleaseStringUTFChars(hashName, name);

	  //Create an Hmac object and initialize it with the created hash.
	  HMAC_CTX_init(ctx);
	  if (0 == (HMAC_Init_ex(ctx, NULL, 0,  md, NULL))) return 0;
	  
	  return (long) ctx;
}

/* 
 * function setKey		: Sets the given key to the given Hmac.
 * param hmac			: Pointer to the native Hmac object.
 * param key			: The key that should be set.
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_prf_openSSL_OpenSSLHMAC_setKey
  (JNIEnv *env, jobject, jlong hmac, jbyteArray key){
	  //Convert the given key into c++ notation.
	  jbyte* keyBytes  = (jbyte*) env->GetByteArrayElements(key, 0);
	  
	  //Initialize the Hmac object with the given key.
	  HMAC_Init_ex((HMAC_CTX *)hmac, keyBytes, env->GetArrayLength(key),  NULL, NULL);
	
	  //Make sure to release the memory created in c++. The JVM will not release it automatically.
	  env->ReleaseByteArrayElements(key, keyBytes, 0);
}

/* 
 * function getNativeBlockSize		: Returns the length of the underlying hash's result.
 */
JNIEXPORT jint JNICALL Java_edu_biu_scapi_primitives_prf_openSSL_OpenSSLHMAC_getNativeBlockSize
  (JNIEnv *, jobject, jlong hmac){
	  //Get the size of the hashed message.
	  return EVP_MD_size(((HMAC_CTX *)hmac)->md);  
}

/* 
 * function getName		: Returns the name of the underlying hash.
 */
JNIEXPORT jstring JNICALL Java_edu_biu_scapi_primitives_prf_openSSL_OpenSSLHMAC_getName
  (JNIEnv *env, jobject, jlong hmac){
	  //Get the type of the hash.
	  int type = EVP_MD_type(((HMAC_CTX *)hmac)->md);
	  //Convert the type to a name.
	  const char* name = OBJ_nid2sn(type);
	  
	  //Return a string that Java can understand with the name of the hash.
	  return env->NewStringUTF(name);
}

/* 
 * function updateNative		: Update teh Hmac object with the given in array
 * param hmac					: Pointer to the native Hmac object.
 * param in						: Input array that should be updated to the Hmac function.
 * param inOffset				: The offset within the input  array that the update should take place from.
 * param len					: The length of the input array.
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_prf_openSSL_OpenSSLHMAC_updateNative
  (JNIEnv *env, jobject, jlong hmac, jbyteArray in, jint inOffset, jint len){
	  //Convert the given data into c++ notation.
	  jbyte* input  = (jbyte*) env->GetByteArrayElements(in, 0);

	  //Update the Hmac object.
	  HMAC_Update((HMAC_CTX*)hmac, (const unsigned char*)(input+inOffset), len);

	  //Release the allocated memory.
	  env->ReleaseByteArrayElements(in, input, 0);
}

/* 
 * function updateFinal		: Finalize the Hmac operation
 * param hmac				: Pointer to the native Hmac object.
 * param out				: Output array that should hols the Hmac's result.
 * param outOffset			: The offset within the output array that the reHmac result should start from.
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_prf_openSSL_OpenSSLHMAC_updateFinal
  (JNIEnv *env, jobject, jlong hmac, jbyteArray out, jint outOffset){
	  
	  int size = EVP_MD_size(((HMAC_CTX *)hmac)->md); //Get the size of the hash output.
	  unsigned char* output = new unsigned char[size];//Create a char array to hold the result.
	  
	  //Compute the final function and copy the output the the given output array
	  if (0 == (HMAC_Final((HMAC_CTX *)hmac, output, NULL))){
		  delete output;
	  }

	  env->SetByteArrayRegion(out, outOffset, size, (jbyte*)output); 

	  //initialize the Hmac again in order to enable repeated calls.
	  const EVP_MD *md = ((HMAC_CTX *)hmac)->md;
	  unsigned char* key = ((HMAC_CTX *)hmac)->key;
	  int keyLen =  ((HMAC_CTX *)hmac)->key_length;
	  if (0 == (HMAC_Init_ex((HMAC_CTX *)hmac, key, keyLen,  md, NULL))){
		  delete(output);
	  }

	  //Release the allocated memory.
	  delete output;
}

/* 
 * function deleteNative		: Deletes the Hmac object.
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_prf_openSSL_OpenSSLHMAC_deleteNative
  (JNIEnv *, jobject, jlong hmac){
	  HMAC_CTX_cleanup((HMAC_CTX*)hmac);
}
