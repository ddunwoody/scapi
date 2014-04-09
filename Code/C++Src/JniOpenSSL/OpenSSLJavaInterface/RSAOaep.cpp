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
#include "RSAOaep.h"
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <iostream>

using namespace std;

JNIEXPORT jlong JNICALL Java_edu_biu_scapi_midLayer_asymmetricCrypto_encryption_OpenSSLRSAOaep_createEncryption
  (JNIEnv *, jobject){
	  //Create a RSA object.
	  RSA* rsa = RSA_new();

	  return (long) rsa;
}


JNIEXPORT void JNICALL Java_edu_biu_scapi_midLayer_asymmetricCrypto_encryption_OpenSSLRSAOaep_initRSAEncryptor
  (JNIEnv *env, jobject, jlong rsa, jbyteArray modulus, jbyteArray pubExponent){
	  
	  jbyte* mod  = (jbyte*) env->GetByteArrayElements(modulus, 0);
	  jbyte* pubExp  = (jbyte*) env->GetByteArrayElements(pubExponent, 0);

	  //Set the given parameters.
	  ((RSA*)rsa)->n = BN_bin2bn((unsigned char*)mod, env->GetArrayLength(modulus), NULL);
	  ((RSA*)rsa)->e = BN_bin2bn((unsigned char*)pubExp, env->GetArrayLength(pubExponent), NULL);

	  //Release the allocated memory.
	  env->ReleaseByteArrayElements(modulus, mod, 0);
	  env->ReleaseByteArrayElements(pubExponent, pubExp, 0);
}


JNIEXPORT void JNICALL Java_edu_biu_scapi_midLayer_asymmetricCrypto_encryption_OpenSSLRSAOaep_initRSADecryptor
  (JNIEnv *env, jobject, jlong rsa, jbyteArray modulus, jbyteArray pubExponent, jbyteArray privExponent){
	  jbyte* mod  = (jbyte*) env->GetByteArrayElements(modulus, 0);
	  jbyte* pubExp  = (jbyte*) env->GetByteArrayElements(pubExponent, 0);
	  jbyte* privExp  = (jbyte*) env->GetByteArrayElements(privExponent, 0);

	  //Set the given parameters.
	  ((RSA*)rsa)->n = BN_bin2bn((unsigned char*)mod, env->GetArrayLength(modulus), NULL);
	  ((RSA*)rsa)->e = BN_bin2bn((unsigned char*)pubExp, env->GetArrayLength(pubExponent), NULL);
	  ((RSA*)rsa)->d = BN_bin2bn((unsigned char*)privExp, env->GetArrayLength(privExponent), NULL);

	  //Release the allocated memory.
	  env->ReleaseByteArrayElements(modulus, mod, 0);
	  env->ReleaseByteArrayElements(pubExponent, pubExp, 0);
	  env->ReleaseByteArrayElements(privExponent, privExp, 0);
}


JNIEXPORT void JNICALL Java_edu_biu_scapi_midLayer_asymmetricCrypto_encryption_OpenSSLRSAOaep_initRSACrtDecryptor
  (JNIEnv *env , jobject, jlong rsa, jbyteArray modulus, jbyteArray pubExponent, jbyteArray privExponent, 
  jbyteArray prime1, jbyteArray prime2, jbyteArray primeExponent1, jbyteArray primeExponent2, jbyteArray crt) {
	  //Convert the given data into c++ notation.
	  jbyte* mod  = (jbyte*) env->GetByteArrayElements(modulus, 0);
	  jbyte* pubExp  = (jbyte*) env->GetByteArrayElements(pubExponent, 0);
	  jbyte* privExp  = (jbyte*) env->GetByteArrayElements(privExponent, 0);
	  jbyte* p  = (jbyte*) env->GetByteArrayElements(prime1, 0);
	  jbyte* q  = (jbyte*) env->GetByteArrayElements(prime2, 0);
	  jbyte* dp  = (jbyte*) env->GetByteArrayElements(primeExponent1, 0);
	  jbyte* dq  = (jbyte*) env->GetByteArrayElements(primeExponent2, 0);
	  jbyte* u  = (jbyte*) env->GetByteArrayElements(crt, 0);
	  
	  
	  //Set the given parameters.
	  ((RSA*)rsa)->n = BN_bin2bn((unsigned char*)mod, env->GetArrayLength(modulus), NULL);
	  ((RSA*)rsa)->e = BN_bin2bn((unsigned char*)pubExp, env->GetArrayLength(pubExponent), NULL);
	  ((RSA*)rsa)->d = BN_bin2bn((unsigned char*)privExp, env->GetArrayLength(privExponent), NULL); 
	  ((RSA*)rsa)->p = BN_bin2bn((unsigned char*)p, env->GetArrayLength(prime1), NULL);
	  ((RSA*)rsa)->q = BN_bin2bn((unsigned char*)q, env->GetArrayLength(prime2), NULL);
	  ((RSA*)rsa)->dmp1 = BN_bin2bn((unsigned char*)dp, env->GetArrayLength(primeExponent1), NULL); 
	  ((RSA*)rsa)->dmq1 = BN_bin2bn((unsigned char*)dq, env->GetArrayLength(primeExponent2), NULL);
	  ((RSA*)rsa)->iqmp = BN_bin2bn((unsigned char*)u, env->GetArrayLength(crt), NULL); 

	  //Release the allocated memory.
	  env->ReleaseByteArrayElements(modulus, mod, 0);
	  env->ReleaseByteArrayElements(pubExponent, pubExp, 0);
	  env->ReleaseByteArrayElements(privExponent, privExp, 0);
	  env->ReleaseByteArrayElements(prime1, p, 0);
	  env->ReleaseByteArrayElements(prime2, q, 0);
	  env->ReleaseByteArrayElements(primeExponent1, dp, 0);
	  env->ReleaseByteArrayElements(primeExponent2, dq, 0);
	  env->ReleaseByteArrayElements(crt, u, 0);

}


JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_midLayer_asymmetricCrypto_encryption_OpenSSLRSAOaep_doEncrypt
  (JNIEnv * env, jobject, jlong rsa, jbyteArray plaintextBytes){
	  
	  jbyte* plaintext  = (jbyte*) env->GetByteArrayElements(plaintextBytes, 0);
	  
	  //Seed the random geneartor.
	  char seed[] = "Seed the PRNG";
	  RAND_seed(seed, sizeof seed);

	  //Allocate a new byte array to hold the output.
	  int size = RSA_size((RSA *) rsa);
	  unsigned char* ret = new unsigned char[size]; 

	  RSA_public_encrypt(env->GetArrayLength(plaintextBytes), (unsigned char*) plaintext, (unsigned char*)ret, (RSA *) rsa, RSA_PKCS1_OAEP_PADDING);

	  //Build jbyteArray from the byteArray.
	  jbyteArray result = env ->NewByteArray(size);
	  env->SetByteArrayRegion(result, 0, size, (jbyte*)ret);
	 
	  //Release the allocated memory.
	  env->ReleaseByteArrayElements(plaintextBytes, plaintext, 0);
	  delete ret;

	  return result;
}


JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_midLayer_asymmetricCrypto_encryption_OpenSSLRSAOaep_doDecrypt
  (JNIEnv *env, jobject, jlong rsa, jbyteArray ciphertext){
	  jbyte* cipher  = (jbyte*) env->GetByteArrayElements(ciphertext, 0);

	  //Allocate a new byte array to hold the output.
	  int size = RSA_size((RSA *) rsa) - 41;
	  unsigned char* ret = new unsigned char[size]; 

	  RSA_private_decrypt(env->GetArrayLength(ciphertext), (unsigned char*) cipher, (unsigned char*)ret, (RSA *) rsa, RSA_PKCS1_OAEP_PADDING);

	  //Build jbyteArray from the byteArray.
	  jbyteArray result = env ->NewByteArray(size);
	  env->SetByteArrayRegion(result, 0, size, (jbyte*)ret);
	 
	  //Release the allocated memory.
	  env->ReleaseByteArrayElements(ciphertext, cipher, 0);
	  delete ret;

	  return result;
}


JNIEXPORT jint JNICALL Java_edu_biu_scapi_midLayer_asymmetricCrypto_encryption_OpenSSLRSAOaep_getPlaintextLength
	(JNIEnv *, jobject, jlong rsa){
		return RSA_size((RSA *) rsa) - 42;
}


JNIEXPORT void JNICALL Java_edu_biu_scapi_midLayer_asymmetricCrypto_encryption_OpenSSLRSAOaep_deleteRSA
  (JNIEnv *, jobject, jlong rsa){
	   RSA_free((RSA *)rsa);
}