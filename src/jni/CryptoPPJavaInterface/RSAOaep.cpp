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
#include <assert.h>
#include <iostream>

// cryptopp includes
#include "cryptlib.h"
#include <osrng.h>
#include <rsa.h>

// local includes
#include "Utils.h"
#include "RSAOaep.h"

using namespace std;
using namespace CryptoPP;


JNIEXPORT jlong JNICALL Java_edu_biu_scapi_midLayer_asymmetricCrypto_encryption_CryptoPPRSAOaep_createRSAEncryptor
  (JNIEnv *, jobject){

	  RSAES_OAEP_SHA_Encryptor* encryptor = new RSAES_OAEP_SHA_Encryptor();

	  //return the encryptor
	  return (jlong) encryptor;
}

/*
 * Class:     edu_biu_scapi_midLayer_asymmetricCrypto_encryption_CryptoPPRSAOaep
 * Method:    createRSADecryptor
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_midLayer_asymmetricCrypto_encryption_CryptoPPRSAOaep_createRSADecryptor
  (JNIEnv *, jobject){
	   
	  RSAES_OAEP_SHA_Decryptor* decryptor = new RSAES_OAEP_SHA_Decryptor();

	  //return the decryptor
	  return (jlong) decryptor;
	  
}



/*
 * Class:     edu_biu_scapi_midLayer_asymmetricCrypto_encryption_CryptoPPRSAOaep
 * Method:    initRSAEncryptor
 * Signature: ([B[B)J
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_midLayer_asymmetricCrypto_encryption_CryptoPPRSAOaep_initRSAEncryptor
  (JNIEnv *env, jobject, jlong encryptor, jbyteArray modulus, jbyteArray pubExp) {
	  
	  Integer n, e;
	  Utils utils;

	  // get the Integers values for the RSA permutation 
	  n = utils.jbyteArrayToCryptoPPInteger(env, modulus);
	  e = utils.jbyteArrayToCryptoPPInteger(env, pubExp);
	  
	  //create pointer to RSAFunction object
	  RSAFunction* rsaFunc = new RSAFunction(); //assign RSAFunction to the pointer

	  //initialize the RSAFunction object with the RSA values
	  rsaFunc->Initialize(n, e);

	  RSA::PublicKey publicKey(*rsaFunc);
	  ((RSAES_OAEP_SHA_Encryptor * ) encryptor)->AccessPublicKey().AssignFrom(publicKey);
}


/*
 * Class:     edu_biu_scapi_midLayer_asymmetricCrypto_encryption_CryptoPPRSAOaep
 * Method:    initRSADecryptor
 * Signature: ([B[B[B)J
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_midLayer_asymmetricCrypto_encryption_CryptoPPRSAOaep_initRSADecryptor
  (JNIEnv *env, jobject, jlong decryptor, jbyteArray modulus, jbyteArray pubExp, jbyteArray privExp) {
	  
	  Integer n, e, d;
	  Utils utils;

	  // get the Integers values for the RSA permutation 
	  n = utils.jbyteArrayToCryptoPPInteger(env, modulus);
	  e = utils.jbyteArrayToCryptoPPInteger(env, pubExp);
	  d = utils.jbyteArrayToCryptoPPInteger(env, privExp);

	  //create pointer to InvertibleRSAFunction object
	  InvertibleRSAFunction* invRsaFunc = new InvertibleRSAFunction;

	  //initialize the trapdoor object with the RSA values
	  invRsaFunc->Initialize(n, e, d);

	  RSA::PrivateKey privateKey(*invRsaFunc);
	  
	  ((RSAES_OAEP_SHA_Decryptor * ) decryptor)->AccessKey().AssignFrom(privateKey);
}

/*
 * Class:     edu_biu_scapi_midLayer_asymmetricCrypto_encryption_CryptoPPRSAOaep
 * Method:    initRSACrtDecryptor
 * Signature: ([B[B[B[B[B[B[B[B)J
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_midLayer_asymmetricCrypto_encryption_CryptoPPRSAOaep_initRSACrtDecryptor
  (JNIEnv *env , jobject, jlong decryptor, jbyteArray modulus, jbyteArray pubExp, jbyteArray privExp, jbyteArray prime1, 
  jbyteArray prime2, jbyteArray primeExponent1, jbyteArray primeExponent2, jbyteArray crt) {

	  Integer n, e, d, p, q, dp, dq, u;
	  Utils utils;

	  // get the Integers values for the RSA permutation 
	  n = utils.jbyteArrayToCryptoPPInteger(env, modulus);
	  e = utils.jbyteArrayToCryptoPPInteger(env, pubExp);
	  d = utils.jbyteArrayToCryptoPPInteger(env, privExp);
	  p = utils.jbyteArrayToCryptoPPInteger(env, prime1);
	  q = utils.jbyteArrayToCryptoPPInteger(env, prime2);
	  dp = utils.jbyteArrayToCryptoPPInteger(env, primeExponent1);
	  dq = utils.jbyteArrayToCryptoPPInteger(env, primeExponent2);
	  u = utils.jbyteArrayToCryptoPPInteger(env, crt);

	  //create pointer to InvertibleRSAFunction object
	  InvertibleRSAFunction *invRsaFunc = new InvertibleRSAFunction;

	  //initialize the invert Rsa Function object with the RSA values
	  invRsaFunc-> Initialize(n, e, d, p, q, dp, dq, u);
	  RSA::PrivateKey privateKey(*invRsaFunc);
	  
	  ((RSAES_OAEP_SHA_Decryptor * ) decryptor)->AccessKey().AssignFrom(privateKey);
}

/*
 * Class:     edu_biu_scapi_midLayer_asymmetricCrypto_encryption_CryptoPPRSAOaep
 * Method:    doEncrypt
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_midLayer_asymmetricCrypto_encryption_CryptoPPRSAOaep_doEncrypt
  (JNIEnv * env, jobject, jlong encryptor, jbyteArray msg){
	
	RSAES_OAEP_SHA_Encryptor * encryptorLocal = (RSAES_OAEP_SHA_Encryptor * )encryptor;

	//Sanity checks of size of plaintext
	if(encryptorLocal->FixedMaxPlaintextLength() ==0) 
		return NULL;

	size_t msgLength = env->GetArrayLength(msg);
	
	if(msgLength > encryptorLocal->FixedMaxPlaintextLength() )
		return NULL;
	
	//Start working
		
	//declare a byte array in c++ where to hold the input msg
	byte *plaintext = (byte*)env->GetByteArrayElements(msg, 0);
	    
	// Create cipher text space
	size_t cipherSize = encryptorLocal->CiphertextLength(msgLength);
	assert( 0 != cipherSize );
	byte *ciphertext = new byte[cipherSize];

	// Actually perform encryption
	AutoSeededRandomPool randPool;
	encryptorLocal->Encrypt( randPool, plaintext, msgLength, ciphertext );
	
	//create a JNI byte array from the ciphertext
	jbyteArray retCipher= env->NewByteArray(cipherSize);
	env->SetByteArrayRegion(retCipher, 0, cipherSize, (jbyte*)ciphertext);
	return retCipher;
}

/*
 * Class:     edu_biu_scapi_midLayer_asymmetricCrypto_encryption_CryptoPPRSAOaep
 * Method:    doDecrypt
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_midLayer_asymmetricCrypto_encryption_CryptoPPRSAOaep_doDecrypt
  (JNIEnv * env, jobject, jlong decryptor, jbyteArray cipher){

    RSAES_OAEP_SHA_Decryptor * decryptorLocal = (RSAES_OAEP_SHA_Decryptor * )decryptor;
	//Sanity checks
    if(decryptorLocal->FixedCiphertextLength() ==0 )
		return NULL;
	size_t cipherLength = env->GetArrayLength(cipher);
    if(cipherLength > decryptorLocal->FixedCiphertextLength() )
		return NULL;

    // Create recovered text space
    size_t recoveredMsgLength = decryptorLocal->MaxPlaintextLength(cipherLength);
    assert( 0 != recoveredMsgLength );
 	byte *recovered = new byte[recoveredMsgLength];


    // Decrypt
	AutoSeededRandomPool randPool;
	//declare a byte array in c++ where to hold the input msg
	byte *ciphertext = (byte*)env->GetByteArrayElements(cipher, 0);
    DecodingResult result = decryptorLocal->Decrypt( randPool, ciphertext, cipherLength, recovered );

    // More sanity checks
    if(!result.isValidCoding )
		return NULL;
    if(result.messageLength >  decryptorLocal->MaxPlaintextLength( cipherLength ) )
		return NULL;
   
	//create a JNI byte array from the ciphertext
	jbyteArray retRecovered= env->NewByteArray(result.messageLength);
	env->SetByteArrayRegion(retRecovered, 0, result.messageLength, (jbyte*)recovered);
	return retRecovered;

}


JNIEXPORT jint JNICALL Java_edu_biu_scapi_midLayer_asymmetricCrypto_encryption_CryptoPPRSAOaep_getPlaintextLength
  (JNIEnv *, jobject, jlong encryptor){

	  return ((RSAES_OAEP_SHA_Encryptor * )encryptor)->FixedMaxPlaintextLength();
}

JNIEXPORT void JNICALL Java_edu_biu_scapi_midLayer_asymmetricCrypto_encryption_CryptoPPRSAOaep_deleteRSA
  (JNIEnv *, jobject, jlong encryptor, jlong decryptor){
         delete (RSAES_OAEP_SHA_Encryptor *) encryptor;
         delete (RSAES_OAEP_SHA_Decryptor *) decryptor;
}
