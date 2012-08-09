#include "stdafx.h"
#include "jni.h" 
#include "AESPermutation.h"
#include "cryptlib.h"
#include "aes.h"
#include <iostream>

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
		  memcpy(inBlock, in+(i*blockSize), blockSize);
		  if (forEncrypt){
			  ((AESEncryption*)aes)->ProcessBlock(inBlock, outBlock);
		  } else {
			  ((AESDecryption*)aes)->ProcessBlock(inBlock, outBlock);
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