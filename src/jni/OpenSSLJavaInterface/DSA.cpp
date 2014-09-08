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
#include "DSA.h"
#include <openssl/dsa.h>
#include <openssl/rand.h>
#include <iostream>

using namespace std;

/* 
 * function createDSA		: This function creates a DSA object that computes the DSA scheme.
 * return					: a pointer to the created object.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_midLayer_asymmetricCrypto_digitalSignature_OpenSSLDSA_createDSA
  (JNIEnv *env, jobject, jbyteArray pBytes, jbyteArray qBytes, jbyteArray gBytes){
	  //Convert the given data into c++ notation.
	  jbyte* p  = (jbyte*) env->GetByteArrayElements(pBytes, 0);
	  jbyte* q  = (jbyte*) env->GetByteArrayElements(qBytes, 0);
	  jbyte* g  = (jbyte*) env->GetByteArrayElements(gBytes, 0);

	  //Create a new DSA object
	  DSA*  dsa = DSA_new();
	  
	  //Set the parameters to the new object.
	  dsa->p = BN_bin2bn((unsigned char*)p, env->GetArrayLength(pBytes), NULL);
	  dsa->q = BN_bin2bn((unsigned char*)q, env->GetArrayLength(qBytes), NULL);
	  dsa->g = BN_bin2bn((unsigned char*)g, env->GetArrayLength(gBytes), NULL);

	  //Release the allocated memory.
	  env->ReleaseByteArrayElements(pBytes, p, 0);
	  env->ReleaseByteArrayElements(qBytes, q, 0);
	  env->ReleaseByteArrayElements(gBytes, g, 0);

	   if (dsa->p == NULL ||  dsa->q == NULL ||  dsa->g == NULL){
		  DSA_free((DSA*) dsa);
		  return 0;
	  }

	  return (long) dsa;
}

/* 
 * function setKeys			 : Set the public and private keys.
							   In this case, the object can verify and sign.
 * param dsa				 : A pointer to the DSA object.
 * param pubKey				 : Public key (y)
 * param privKey			 : Private key (x)
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_midLayer_asymmetricCrypto_digitalSignature_OpenSSLDSA_setKeys
  (JNIEnv * env, jobject, jlong dsa, jbyteArray pubKey, jbyteArray privKey){
	  //Convert the given data into c++ notation.
	  jbyte* publicKey  = (jbyte*) env->GetByteArrayElements(pubKey, 0);
	  jbyte* privateKey  = (jbyte*) env->GetByteArrayElements(privKey, 0);

	  //Set the keys parameters to the given object.
	  ((DSA*)dsa)->pub_key = BN_bin2bn((unsigned char*)publicKey, env->GetArrayLength(pubKey), NULL);
	  ((DSA*)dsa)->priv_key = BN_bin2bn((unsigned char*)privateKey, env->GetArrayLength(privKey), NULL);

	  //Release the allocated memory.
	  env->ReleaseByteArrayElements(pubKey, publicKey, 0);
	  env->ReleaseByteArrayElements(privKey, privateKey, 0);
}

/* 
 * function setPublicKey	 : Set the public key.
							   In this case, the object can verify but cannot sign.
 * param dsa				 : A pointer to the DSA object.
 * param pubKey				 : Public key (y)
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_midLayer_asymmetricCrypto_digitalSignature_OpenSSLDSA_setPublicKey
  (JNIEnv *env, jobject, jlong dsa, jbyteArray pubKey){
	  //Convert the given data into c++ notation.
	  jbyte* publicKey  = (jbyte*) env->GetByteArrayElements(pubKey, 0);

	  //Set the key parameter to the given object.
	  ((DSA*)dsa)->pub_key = BN_bin2bn((unsigned char*)publicKey, env->GetArrayLength(pubKey), NULL);

	  //Release the allocated memory.
	  env->ReleaseByteArrayElements(pubKey, publicKey, 0);
}

/*
 * function sign				: Signs the given message.
 * param dsa					: A pointer to the DSA object.
 * param msg					: The message to sign.
 * param offset					: The offset within the message to take the bytes from.
 * param len					: The length of the message to sign.
 * return jbyteArray			: The signature bytes.
 */
JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_midLayer_asymmetricCrypto_digitalSignature_OpenSSLDSA_sign
  (JNIEnv * env, jobject, jlong dsa, jbyteArray msg, jint offset, jint len){
	  //Convert the given data into c++ notation.
	  jbyte* message  = (jbyte*) env->GetByteArrayElements(msg, 0);
	  
	  //Seed the random geneartor.
#ifdef _WIN32
	  RAND_screen(); // only defined for windows, reseeds from screen contents
#else
	  RAND_poll(); // reseeds using hardware state (clock, interrupts, etc).
#endif

	  //Allocate a new byte array to hold the output.
	  int size = DSA_size((DSA *) dsa);
	  unsigned char* sig = new unsigned char[size]; 
	  unsigned int siglen;

	  //Sign the message.
	  DSA_sign(0, (unsigned char*) message + offset, len, sig, &siglen, (DSA*) dsa);

	  //Build jbyteArray from the byteArray.
	  jbyteArray result = env ->NewByteArray(size);
	  env->SetByteArrayRegion(result, 0, size, (jbyte*)sig);
	 
	  //Release the allocated memory.
	  env->ReleaseByteArrayElements(msg, message, 0);
	  delete sig;

	  return result;
}

/*
 * function verify			: Verify the given signature with the given message.
 * param dsa				: A pointer to the DSA object.
 * param signature			: The signature to verify.
 * param msg				: The message to sign.
 * param offset				: The offset within the message to take the bytes from.
 * param len				: The length of the message to sign.
 * return jboolean			: True, if the given signature is valid. False, otherwise.
 */
JNIEXPORT jboolean JNICALL Java_edu_biu_scapi_midLayer_asymmetricCrypto_digitalSignature_OpenSSLDSA_verify
  (JNIEnv * env, jobject, jlong dsa, jbyteArray signature, jbyteArray msg, jint offset, jint len){
	  //Convert the given data into c++ notation.
	  jbyte* message  = (jbyte*) env->GetByteArrayElements(msg, 0);
	  jbyte* sig  = (jbyte*) env->GetByteArrayElements(signature, 0);

	  //Verify teh signature.
	  bool result = DSA_verify(0, (unsigned char*) message + offset, len, (unsigned char*) sig, env->GetArrayLength(signature), (DSA*) dsa);

	  //Release the allocated memory.
	  env->ReleaseByteArrayElements(msg, message, 0);
	  env->ReleaseByteArrayElements(signature, sig, 0);

	  return result;
}

/*
 * function generateKey		: Generates public and private key to a DSA scheme.
 * param dsa				: A pointer to a DSA object.
 */
JNIEXPORT jobjectArray JNICALL Java_edu_biu_scapi_midLayer_asymmetricCrypto_digitalSignature_OpenSSLDSA_generateKey
  (JNIEnv *env, jobject, jlong dsa){
	 //Generate DSA keys. The keys are stored in the DSA structure.
	 if (0 == (DSA_generate_key((DSA*) dsa))){
		 return 0;
	 }
	  
	 //Build a jObjectArray to hold the keys data.
	 jclass byteClass = env->FindClass("[B");
	 jobjectArray keys = env ->NewObjectArray(2, byteClass, NULL);

	 //Get the public key bytes.
	 char* y = new char[BN_num_bytes(((DSA*) dsa)->pub_key)];
	 int len = BN_bn2bin(((DSA*) dsa)->pub_key, (unsigned char*)y);
	 //Copy the bytes into a jByteArray.
	 jbyteArray yArray = env ->NewByteArray(len);
	 env->SetByteArrayRegion(yArray, 0, len, (jbyte*)y);
	 //Put the public key bytes in the first cell in the objects array.
	 env->SetObjectArrayElement(keys, 0, yArray);
	  
	 //Get the private key bytes.
	 char* x = new char[BN_num_bytes(((DSA*) dsa)->priv_key)];
	 len = BN_bn2bin(((DSA*) dsa)->priv_key, (unsigned char*)x);
	  //Copy the bytes into a jByteArray.
	 jbyteArray xArray = env ->NewByteArray(len);
	 env->SetByteArrayRegion(xArray, 0, len, (jbyte*)x);
	 //Put the private key bytes in the second cell in the objects array.
	 env->SetObjectArrayElement(keys, 1, xArray);
	  
	 //The generated keys should not be set to this object. Release them.
	 ((DSA*) dsa)->pub_key = NULL;
	 ((DSA*) dsa)->priv_key = NULL;
	 
	 //Deltes the allocated memory.
	 delete y; 
	 delete x;

	 return keys;
}

/*
 * function deleteDSA			: Deletes the native DSA object.
 * param dsa					: A pointer to the DSA object.
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_midLayer_asymmetricCrypto_digitalSignature_OpenSSLDSA_deleteDSA
  (JNIEnv *, jobject, jlong dsa){
	  DSA_free((DSA*) dsa);
}
