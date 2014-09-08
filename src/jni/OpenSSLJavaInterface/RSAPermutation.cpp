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
#include "RSAPermutation.h"
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <iostream>
#include <openssl/err.h>

using namespace std;

/*
 * function initRSAPublicPrivate	: Creates and initializes a RSA object with public key and private key.
 * param modulus					: modolus (n)
 * param pubExponent				: pubic exponent (e)
 * param privExponent				: private exponent (d)
 * return jlong						: pointer to the native object
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_trapdoorPermutation_openSSL_OpenSSLRSAPermutation_initRSAPublicPrivate
  (JNIEnv *env, jobject, jbyteArray modulus, jbyteArray pubExponent, jbyteArray privExponent){
	  //Create a RSA object.
	  RSA* rsa = RSA_new();

	  //Convert the given data into c++ notation.
	  jbyte* mod  = (jbyte*) env->GetByteArrayElements(modulus, 0);
	  jbyte* pubExp  = (jbyte*) env->GetByteArrayElements(pubExponent, 0);
	  jbyte* privExp  = (jbyte*) env->GetByteArrayElements(privExponent, 0);

	  //Set the given parameters.
	  rsa->n = BN_bin2bn((unsigned char*)mod, env->GetArrayLength(modulus), NULL);
	  rsa->e = BN_bin2bn((unsigned char*)pubExp, env->GetArrayLength(pubExponent), NULL);
	  rsa->d = BN_bin2bn((unsigned char*)privExp, env->GetArrayLength(privExponent), NULL); 

	  //Release the allocated memory.
	  env->ReleaseByteArrayElements(modulus, mod, 0);
	  env->ReleaseByteArrayElements(pubExponent, pubExp, 0);
	  env->ReleaseByteArrayElements(privExponent, privExp, 0);

	  if ((rsa->n == NULL) || (rsa->e == NULL) || (rsa->d == NULL)){
		  RSA_free((RSA *)rsa);
		  return 0;
	  }

	  return (long) rsa;
}

/*
 * function initRSAPublicPrivateCrt	: Creates and initializes a RSA object with public key and private CRT key.
 * param modulus					: modolus (n)
 * param pubExponent				: pubic exponent (e)
 * param privExponent				: private exponent (d)
 * param prime1						: The prime p, such that p * q = n.
 * param prime2						: The prime q, such that p * q = n.
 * param primeExponent1				: dp, suzh that e * dp = 1 mod(p-1)
 * param primeExponent2				: dq, suzh that e * dq = 1 mod(q-1)
 * params crt						: q^(-1) mod p.
 * return jlong						: pointer to the native object
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_trapdoorPermutation_openSSL_OpenSSLRSAPermutation_initRSAPublicPrivateCrt
  (JNIEnv *env , jobject, jbyteArray modulus, jbyteArray pubExponent, jbyteArray privExponent, jbyteArray prime1, 
  jbyteArray prime2, jbyteArray primeExponent1, jbyteArray primeExponent2, jbyteArray crt) {
	  //Convert the given data into c++ notation.
	  jbyte* mod  = (jbyte*) env->GetByteArrayElements(modulus, 0);
	  jbyte* pubExp  = (jbyte*) env->GetByteArrayElements(pubExponent, 0);
	  jbyte* privExp  = (jbyte*) env->GetByteArrayElements(privExponent, 0);
	  jbyte* p  = (jbyte*) env->GetByteArrayElements(prime1, 0);
	  jbyte* q  = (jbyte*) env->GetByteArrayElements(prime2, 0);
	  jbyte* dp  = (jbyte*) env->GetByteArrayElements(primeExponent1, 0);
	  jbyte* dq  = (jbyte*) env->GetByteArrayElements(primeExponent2, 0);
	  jbyte* u  = (jbyte*) env->GetByteArrayElements(crt, 0);
	  
	  //Create a RSA object.
	  RSA* rsa = RSA_new();
	  //Set the given parameters.
	  rsa->n = BN_bin2bn((unsigned char*)mod, env->GetArrayLength(modulus), NULL);
	  rsa->e = BN_bin2bn((unsigned char*)pubExp, env->GetArrayLength(pubExponent), NULL);
	  rsa->d = BN_bin2bn((unsigned char*)privExp, env->GetArrayLength(privExponent), NULL); 
	  rsa->p = BN_bin2bn((unsigned char*)p, env->GetArrayLength(prime1), NULL);
	  rsa->q = BN_bin2bn((unsigned char*)q, env->GetArrayLength(prime2), NULL);
	  rsa->dmp1 = BN_bin2bn((unsigned char*)dp, env->GetArrayLength(primeExponent1), NULL); 
	  rsa->dmq1 = BN_bin2bn((unsigned char*)dq, env->GetArrayLength(primeExponent2), NULL);
	  rsa->iqmp = BN_bin2bn((unsigned char*)u, env->GetArrayLength(crt), NULL); 

	  //Release the allocated memory.
	  env->ReleaseByteArrayElements(modulus, mod, 0);
	  env->ReleaseByteArrayElements(pubExponent, pubExp, 0);
	  env->ReleaseByteArrayElements(privExponent, privExp, 0);
	  env->ReleaseByteArrayElements(prime1, p, 0);
	  env->ReleaseByteArrayElements(prime2, q, 0);
	  env->ReleaseByteArrayElements(primeExponent1, dp, 0);
	  env->ReleaseByteArrayElements(primeExponent2, dq, 0);
	  env->ReleaseByteArrayElements(crt, u, 0);

	  if ((rsa->n == NULL) || (rsa->e == NULL) || (rsa->d == NULL) || (rsa->p == NULL) || (rsa->q == NULL) || (rsa->dmp1 == NULL) || (rsa->dmq1 == NULL) || (rsa->iqmp == NULL)){
		  RSA_free((RSA *)rsa);
		  return 0;
	  }

	  return (long) rsa;
}

/*
 * function initRSAPublic	: Creates and initializes a RSA object with public key.
 * param modulus			: modolus (n)
 * param pubExponent		: pubic exponent (e)
 * return jlong				: pointer to the native object
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_trapdoorPermutation_openSSL_OpenSSLRSAPermutation_initRSAPublic
  (JNIEnv *env, jobject, jbyteArray modulus, jbyteArray pubExponent) {
	  //Convert the given data into c++ notation.
	  jbyte* mod  = (jbyte*) env->GetByteArrayElements(modulus, 0);
	  jbyte* pubExp  = (jbyte*) env->GetByteArrayElements(pubExponent, 0);

	  //Create a RSA object.
	  RSA* rsa = RSA_new();
	  //Set the given parameters.
	  rsa->n = BN_bin2bn((unsigned char*)mod, env->GetArrayLength(modulus), NULL);
	  rsa->e = BN_bin2bn((unsigned char*)pubExp, env->GetArrayLength(pubExponent), NULL);

	  //Release the allocated memory.
	  env->ReleaseByteArrayElements(modulus, mod, 0);
	  env->ReleaseByteArrayElements(pubExponent, pubExp, 0);

	  if ((rsa->n == NULL) || (rsa->e == NULL)){
		  RSA_free((RSA *)rsa);
		  return 0;
	  }
	  return (long) rsa;
}

/*
 * function computeRSA		: Computes the RSA permutation on the given element.
 * param rsa				: Pointer to the native RSA object.
 * param element			: Bytes of the element to compute the permutation on.
 * return jbyteArray		: The bytes of the result's element.
 */
JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_primitives_trapdoorPermutation_openSSL_OpenSSLRSAPermutation_computeRSA
  (JNIEnv *env, jobject, jlong rsa, jbyteArray element) {
	  //Convert the given data into c++ notation.
	  jbyte* el  = (jbyte*) env->GetByteArrayElements(element, 0);
	  ERR_load_crypto_strings();

	  //Seed the random geneartor.
#ifdef _WIN32
	  RAND_screen(); // only defined for windows, reseeds from screen contents
#else
	  RAND_poll(); // reseeds using hardware state (clock, interrupts, etc).
#endif

	  //Allocate a new byte array to hold the output.
	  int size = RSA_size((RSA *) rsa);
	  unsigned char* ret = new unsigned char[size]; 
	  
	  //Compute the RSA permutation on the given bytes.
	  // In java, BigInteger can have 0 in the first byte in order the BigInteger to be positive. 
	  // When we convert it to byte array, we need to ignore the first zero in order to get a plaintext in the right size.
	  if ((int)el[0] == 0){
		  RSA_public_encrypt(env->GetArrayLength(element)-1, (unsigned char*) el+1, (unsigned char*)ret, (RSA *) rsa, RSA_NO_PADDING);
	  }else{
		  RSA_public_encrypt(env->GetArrayLength(element), (unsigned char*) el, (unsigned char*)ret, (RSA *) rsa, RSA_NO_PADDING);
	  }
	  
	  //Build jbyteArray from the byteArray.
	  jbyteArray result = env ->NewByteArray(size);
	  env->SetByteArrayRegion(result, 0, size, (jbyte*)ret);
	 
	  //Release the allocated memory.
	  env->ReleaseByteArrayElements(element, el, 0);
	  delete ret;

	  return result;
}

/*
 * function invertRSA		: Inverts the RSA permutation on the given element.
 * param rsa				: Pointer to the native RSA object.
 * param element			: Bytes of the element to compute the permutation on.
 * return jbyteArray		: The bytes of the result's element.
 */
JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_primitives_trapdoorPermutation_openSSL_OpenSSLRSAPermutation_invertRSA
  (JNIEnv *env, jobject, jlong rsa, jbyteArray element){
	  //Convert the given data into c++ notation.
	  jbyte* el  = (jbyte*) env->GetByteArrayElements(element, 0);
	  
	  //Allocate a new byte array to hold the output.
	  int size = RSA_size((RSA *) rsa);
	  unsigned char* ret = new unsigned char[size]; 

	  //Invert the RSA permutation on the given bytes.
	  // In java, BigInteger can have 0 in the first byte in order the BigInteger to be positive. 
	  // When we convert it to byte array, we need to ignore the first zero in order to get a ciphertext in the right size.
	  if ((int) el[0] == 0){
		  RSA_private_decrypt(env->GetArrayLength(element)-1, (unsigned char*) el+1, ret, (RSA *) rsa, RSA_NO_PADDING);
	  }else{
		  RSA_private_decrypt(env->GetArrayLength(element), (unsigned char*) el, ret, (RSA *) rsa, RSA_NO_PADDING);
	  }

	  //Build jbyteArray from the byteArray.
	  jbyteArray result = env ->NewByteArray(size);
	  env->SetByteArrayRegion(result, 0, size, (jbyte*)ret);

	  //Release the allocated memory.
	  env->ReleaseByteArrayElements(element, el, 0);
	  delete ret;

	  return result;
}

/*
 * function deleteRSA		: Deletes the native RSA object. 
 * param rsa				: Pointer to the native RSA object.
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_trapdoorPermutation_openSSL_OpenSSLRSAPermutation_deleteRSA
  (JNIEnv *, jobject, jlong  rsa){
	  RSA_free((RSA *)rsa);
}
