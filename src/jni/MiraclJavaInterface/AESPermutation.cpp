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

// visual studio precompiled headers
#include "stdafx.h"

#include <jni.h>
#include <stdlib.h>
#include <iostream>
#include <string.h>

extern "C" {
#include <miracl.h>
}
#include "AESPermutation.h"

using namespace std;

/* function createAES : This function initializes the aes structure defined in miracl.h
 * param keyBytes	  : the key for AES permutation
 * return			  : the created aes pointer.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_prf_miracl_MiraclAES_createAES
  (JNIEnv *env, jobject, jbyteArray keyBytes){

	  int len = env->GetArrayLength(keyBytes);
	  jbyte* key = env->GetByteArrayElements(keyBytes, 0);
	  
	  //Initialize aes object and set the key.
	  aes* aesPointer = new aes;
	  bool valid = aes_init(aesPointer, MR_ECB, len, (char*)key, NULL);
	  
	  env->ReleaseByteArrayElements(keyBytes, key, 0);
	 
	  return (long)aesPointer;
}

/* function computeBlock : This function computes the aes permutation
 * param aesPointer		 : pointer to the aes struct
 * param inBytes		 : byte array to compute the aes permutation on.
 * param inOff			 : offset in the input byte array indicates the start point to begin the aes computation.
 * param outBytes		 : output bytes. The resulted bytes of compute.
 * param outOff			 : offset in the outBytes array to put the result from.
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_prf_miracl_MiraclAES_computeBlock
  (JNIEnv *env, jobject, jlong aesPointer, jbyteArray inBytes, jint inOff, jbyteArray outBytes, jint outOff){
	
	  jbyte *in =  env->GetByteArrayElements(inBytes, 0);
	  jbyte *out = env->GetByteArrayElements(outBytes, 0);
	  
	  //aes_encrypt function gets an input array to compute and put the result in the same array.
	  //In order not to change the input array we copy the it to the output array. 
	  //This way the compute output will be in the output array, as we want.
	  memcpy(out+outOff, in+inOff, 16);
	  
	  //Compute the data given in the input byte array. 
	  //The computed data will be in the output array after the computation.
	  aes_encrypt((aes*)aesPointer, ((char*)out)+outOff);
	 
	  //Make sure to release the memory created in c++. The JVM will not release it automatically.
	  env->ReleaseByteArrayElements(inBytes, in, 0);
	  env->ReleaseByteArrayElements(outBytes, out, 0);
}

/* function invertBlock  : This function computes the aes permutation
 * param aesPointer		 : pointer to the aes struct
 * param inBytes		 : byte array to invert the aes permutation on.
 * param inOff			 : offset in the input byte array indicates the start point to begin the aes invert.
 * param outBytes		 : output bytes. The resulted bytes of invert.
 * param outOff			 : offset in the outBytes array to put the result from.
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_prf_miracl_MiraclAES_invertBlock
  (JNIEnv *env, jobject, jlong aesPointer, jbyteArray inBytes, jint inOff, jbyteArray outBytes, jint outOff){
	  
	  jbyte *in =  env->GetByteArrayElements(inBytes, 0);
	  jbyte *out = env->GetByteArrayElements(outBytes, 0);

	  //aes_decrypt function gets an input array to invert and put the result in the same array.
	  //In order not to change the input array we copy the it to the output array. 
	  //This way the invert output will be in the output array, as we want.
	  memcpy(out+outOff, in+inOff, 16);

	  //Invert the data given in the input byte array. 
	  //The inverted data will be in the output array after the invertion.
	  aes_decrypt((aes*)aesPointer, ((char*)out)+outOff);

	  //Make sure to release the memory created in c++. The JVM will not release it automatically.
	  env->ReleaseByteArrayElements(inBytes, in, 0);
	  env->ReleaseByteArrayElements(outBytes, out, 0);
}

/* function optimizedCompute	: This function computes the AES permutation on a big byte array, by computing each block separately.
 * param aesPointer				: pointer to the aes struct
 * param inBytes				: byte array to compute the aes permutation on.
 * param outBytes				: output bytes. The resulted bytes of compute.
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_prf_miracl_MiraclAES_optimizedCompute
  (JNIEnv *env, jobject, jlong aesPointer, jbyteArray inBytes, jbyteArray outBytes){
	  
	  jbyte *in = env->GetByteArrayElements(inBytes, 0);
	  
	  int blockSize = 16; //In AES permutation in a CBC mode the block size is fixed, 16 bytes. 

	  int rounds = (env->GetArrayLength(inBytes))/blockSize; //Calculate the number of blocks to compute

	  //Prepare array to use in the AES permutation.
	  char* inBlock = new char[blockSize];

	  //For each block, compute the AES permutation and put the result in the output aray
	  for (int i=0; i<rounds; i++){
		  memcpy(inBlock, in+(i*blockSize), blockSize);
		  
		  aes_encrypt((aes*)aesPointer, inBlock);
		  
		  env->SetByteArrayRegion(outBytes, i*blockSize, blockSize, (jbyte*)inBlock);
	  }
	  delete(inBlock);
	  //make sure to release the memory created in c++. The JVM will not release it automatically.
	  env->ReleaseByteArrayElements(inBytes,in,0);
}

/* function optimizedInvert	: This function inverts the AES permutation on a big byte array, by inverting each block separately.
 * param aesPointer			: pointer to the aes struct
 * param inBytes			: byte array to invert the aes permutation on.
 * param outBytes			: output bytes. The resulted bytes of invert.
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_prf_miracl_MiraclAES_optimizedInvert
  (JNIEnv *env, jobject, jlong aesPointer, jbyteArray inBytes, jbyteArray outBytes){
	  
	  jbyte *in = env->GetByteArrayElements(inBytes, 0);
	  
	  int blockSize = 16; //In AES permutation in a CBC mode the block size is fixed, 16 bytes. 

	  int rounds = (env->GetArrayLength(inBytes))/blockSize; //Calculate the number of blocks to invert

	  //Prepare array to use in the AES permutation.
	  char* inBlock = new char[blockSize];

	  //For each block, invert the AES permutation and put the result in the output aray
	  for (int i=0; i<rounds; i++){
		  memcpy(inBlock, in+(i*blockSize), blockSize);
		  
		  aes_decrypt((aes*)aesPointer, inBlock);
		  
		  env->SetByteArrayRegion(outBytes, i*blockSize, blockSize, (jbyte*)inBlock);
	  }
	  delete(inBlock);
	  //make sure to release the memory created in c++. The JVM will not release it automatically.
	  env->ReleaseByteArrayElements(inBytes,in,0);
}

/* function deleteAES	: This function deletes the allocated memory for the AES permutation.
 * param aesPointer		: pointer to the aes struct
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_prf_miracl_MiraclAES_deleteAES
  (JNIEnv *, jobject, jlong aesPointer){
	  aes_end((aes*) aesPointer);
}
