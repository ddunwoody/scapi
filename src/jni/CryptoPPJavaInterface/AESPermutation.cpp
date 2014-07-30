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
// windows includes
#include "StdAfx.h"

// stdlib includes
#include <iostream>

// java jni includes
#include "jni.h"

// cryptopp includes
#include "cryptlib.h"
#include "aes.h"

// local includes
#include "AESPermutation.h"

using namespace std;
using namespace CryptoPP;


JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_prf_cryptopp_CryptoPpAES_createAESCompute
  (JNIEnv *, jobject){
	  AESEncryption* aes = new AESEncryption();
	  return (long) aes;
}

JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_prf_cryptopp_CryptoPpAES_createAESInvert
	(JNIEnv *, jobject){
	  AESDecryption* aes = new AESDecryption();
	  return (long) aes;
}


JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_prf_cryptopp_CryptoPpAES_setNativeKey
  (JNIEnv *env, jobject, jlong aesCompute, jlong aesInvert, jbyteArray keyBytes){

	  jbyte *key = env->GetByteArrayElements(keyBytes, 0);
	  
	  ((AESEncryption*)aesCompute)->SetKey((byte*)key, env->GetArrayLength(keyBytes));
	  ((AESDecryption*)aesInvert)->SetKey((byte*)key, env->GetArrayLength(keyBytes));

	  //make sure to release the memory created in c++. The JVM will not release it automatically.
	env->ReleaseByteArrayElements(keyBytes,key,0);
}

JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_prf_cryptopp_CryptoPpAES_computeBlock
  (JNIEnv *env, jobject, jlong aes, jbyteArray inBytes, jbyteArray outBytes, jint outOffset, jboolean forEncrypt){

	  jbyte *in = env->GetByteArrayElements(inBytes, 0);
	  jbyte *out = env->GetByteArrayElements(outBytes, 0);
	  
	  if (forEncrypt){
		 ((AESEncryption*)aes)->ProcessBlock((byte*)in, (byte*) out);
		 env->SetByteArrayRegion(outBytes, outOffset, ((AESEncryption*)aes)->BlockSize(), out);
	  } else {
		  ((AESDecryption*)aes)->ProcessBlock((byte*)in, (byte*) out);
		  env->SetByteArrayRegion(outBytes, outOffset, ((AESDecryption*)aes)->BlockSize(), out);
	  }

	  //make sure to release the memory created in c++. The JVM will not release it automatically.
	  env->ReleaseByteArrayElements(inBytes,in,0);
	  env->ReleaseByteArrayElements(outBytes,out,0);
}

JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_prf_cryptopp_CryptoPpAES_optimizedCompute
  (JNIEnv *env, jobject, jlong aes, jbyteArray inBytes, jbyteArray outBytes, jboolean forEncrypt){

	  jbyte *in = env->GetByteArrayElements(inBytes, 0);
	  
	  int blockSize;
	  if (forEncrypt){
		blockSize = ((AESEncryption*)aes)->BlockSize();
	  } else {
		  blockSize = ((AESDecryption*)aes)->BlockSize();
	  }

	  int rounds = (env->GetArrayLength(inBytes))/blockSize;
	  byte* inBlock = new byte[blockSize];
	  byte* outBlock = new byte[blockSize];

	  for (int i=0; i<rounds; i++){
		  //memcpy(inBlock, in+(i*blockSize), blockSize);
		  if (forEncrypt){
			  ((AESEncryption*)aes)->ProcessBlock((byte*)(in+(i*blockSize)), outBlock);
		  } else {
			  ((AESDecryption*)aes)->ProcessBlock((byte*)(in+(i*blockSize)), outBlock);
		  }
		  env->SetByteArrayRegion(outBytes, i*blockSize, blockSize, (jbyte*)outBlock);
	  }

	  //make sure to release the memory created in c++. The JVM will not release it automatically.
	  env->ReleaseByteArrayElements(inBytes,in,0);
}

JNIEXPORT jstring JNICALL Java_edu_biu_scapi_primitives_prf_cryptopp_CryptoPpAES_getName
  (JNIEnv *env, jobject, jlong aes){
	  string name = ((AESEncryption*)aes)->AlgorithmName();

	 return  env->NewStringUTF(name.c_str());
}

JNIEXPORT jint JNICALL Java_edu_biu_scapi_primitives_prf_cryptopp_CryptoPpAES_getBlockSize
  (JNIEnv *, jobject, jlong aes){
	  return ((AESEncryption*)aes)->BlockSize();
}

JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_prf_cryptopp_CryptoPpAES_deleteAES
  (JNIEnv *, jobject, jlong aesCompute, jlong aesInvert){
	  delete((AESEncryption*)aesCompute);
	  delete((AESEncryption*)aesInvert);
}
