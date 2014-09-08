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
#include "SymEncryption.h"
#include <openssl/evp.h>
#include <iostream>
#include <cstring>

using namespace std;

/* 
 * function createEncryption		: Creates an EVP_CIPHER_CTX object that perform the encryption.
 * return							: a pointer to the created object.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_midLayer_symmetricCrypto_encryption_OpenSSLEncWithIVAbs_createEncryption
  (JNIEnv *, jobject){
	  //Create a new cipher.
	  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	  
	  return (long) ctx;
}

/* 
 * function createDecryption		: Creates an EVP_CIPHER_CTX object that perform the decryption.
 * return							: a pointer to the created object.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_midLayer_symmetricCrypto_encryption_OpenSSLEncWithIVAbs_createDecryption
  (JNIEnv *, jobject){
	  //Create a new cipher.
	  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	  
	  return (long) ctx;
}

/* 
 * function getIVSize		: Returns the Iv size of the current encryption.
							  The Iv size depends on the mode of operation.
 * return					: the IV size.
 */
JNIEXPORT jint JNICALL Java_edu_biu_scapi_midLayer_symmetricCrypto_encryption_OpenSSLEncWithIVAbs_getIVSize
  (JNIEnv *, jobject, jlong enc){
	  return EVP_CIPHER_CTX_iv_length((EVP_CIPHER_CTX *)enc);
}

/* 
 * function encrypt			: Encrypts the given plaintext using the given iv.
 * param enc				: A pointer to the native object that does the encryption.
 * param plaintextBytes		: The bytes of the plaintext that should be encrypt.
 * return					: The encrypted data.
 */
JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_midLayer_symmetricCrypto_encryption_OpenSSLEncWithIVAbs_encrypt
  (JNIEnv *env, jobject, jlong enc, jbyteArray plaintextBytes, jbyteArray ivBytes){
	  
	  //Convert the given data into c++ notation.
	  jbyte* plaintext  = (jbyte*) env->GetByteArrayElements(plaintextBytes, 0);
	  jbyte* iv  = (jbyte*) env->GetByteArrayElements(ivBytes, 0);
	  
	  //Initialize the encryption objects with the key.
	  if (0 == (EVP_EncryptInit ((EVP_CIPHER_CTX *)enc, NULL, NULL, (unsigned char*) iv))){
		  env->ReleaseByteArrayElements(plaintextBytes, plaintext, 0);
		  env->ReleaseByteArrayElements(ivBytes, iv, 0);
		  return 0;
	  }
	  
	  int blockSize = EVP_CIPHER_CTX_block_size((EVP_CIPHER_CTX *)enc);
	  int plaintextSize = env->GetArrayLength(plaintextBytes);  

	  //Before the encryption, tha plaintext should be padded.
	  //The padding scheme aligns the plaintext to size blockSize (and if the plaintext already aligned, it add an entire blockSize bytes.
	  //As a result, the size of the ciphertext should be at most of size plaintextSize + blockSize.
	  unsigned char* out  = new unsigned char[plaintextSize+blockSize];

	  int size, rem;
	  
	  //Encrypt the plaintext.
	  if (0 == (EVP_EncryptUpdate ((EVP_CIPHER_CTX*)enc, out, &size, (unsigned char*)plaintext, plaintextSize))){
		  env->ReleaseByteArrayElements(plaintextBytes, plaintext, 0);
		  env->ReleaseByteArrayElements(ivBytes, iv, 0);
		  delete (out);
		  return 0;
	  }
	  if(0 == EVP_EncryptFinal_ex((EVP_CIPHER_CTX*)enc, out+size, &rem)){
		  env->ReleaseByteArrayElements(plaintextBytes, plaintext, 0);
		  env->ReleaseByteArrayElements(ivBytes, iv, 0);
		  delete (out);
		  return 0;
	  }
		 
	  //Create a jbyteArray that contains the encrypted data.
	  jbyteArray result = env ->NewByteArray(size+rem);
	  env->SetByteArrayRegion(result, 0, size+rem, (jbyte*)out);
	 
	  //Make sure to release the memory created in c++. The JVM will not release it automatically.
	  env->ReleaseByteArrayElements(plaintextBytes, plaintext, 0);
	  env->ReleaseByteArrayElements(ivBytes, iv, 0);
	  delete (out);

	  return result;
}

/* 
 * function decrypt			: Encrypts the given plaintext using the given iv.
 * param dec				: A pointer to the native object that does the decryption.
 * param cipherBytes		: The bytes of the ciphertext that should be decrypted.
 * return					: The decrypted data.
 */
JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_midLayer_symmetricCrypto_encryption_OpenSSLEncWithIVAbs_decrypt
  (JNIEnv *env, jobject, jlong dec, jbyteArray cipherBytes, jbyteArray ivBytes){	  
	  //Convert the given data into c++ notation.
	  jbyte* cipher  = (jbyte*) env->GetByteArrayElements(cipherBytes, 0);
	  jbyte* iv  = (jbyte*) env->GetByteArrayElements(ivBytes, 0);
	  
	   //Initialize the encryption object with the key.
	  if (0 == EVP_DecryptInit ((EVP_CIPHER_CTX *)dec, NULL, NULL, (unsigned char*) iv)){
		  env->ReleaseByteArrayElements(cipherBytes, cipher, 0);
		  env->ReleaseByteArrayElements(ivBytes, iv, 0);
		  return 0;
	  }
	  
	  int cipherSize = env->GetArrayLength(cipherBytes);  
	  //Allocate a new byte array of size cipherSize.
	  unsigned char* out = new unsigned char[cipherSize];
	  
	  int size, rem;
	  
	  //Decrypt the ciphertext.
	  if (0 == (EVP_DecryptUpdate ((EVP_CIPHER_CTX*)dec, out, &size, (unsigned char*)cipher, cipherSize))){
		  env->ReleaseByteArrayElements(cipherBytes, cipher, 0);
		  env->ReleaseByteArrayElements(ivBytes, iv, 0);
		  delete(out);
		  return 0;
	  }
	  if (0 == (EVP_DecryptFinal_ex((EVP_CIPHER_CTX*)dec, out+size, &rem))){
		  env->ReleaseByteArrayElements(cipherBytes, cipher, 0);
		  env->ReleaseByteArrayElements(ivBytes, iv, 0);
		  delete(out);
		  return 0;
	  }
		 
	  //Create a jbyteArray that contains the decrypted data.
	  jbyteArray result = env ->NewByteArray(size+rem);
	  env->SetByteArrayRegion(result, 0, size+rem, (jbyte*)out);
	 
	  //Make sure to release the memory created in c++. The JVM will not release it automatically.
	  env->ReleaseByteArrayElements(cipherBytes, cipher, 0);
	  env->ReleaseByteArrayElements(ivBytes, iv, 0);
	  delete (out);

	  return result;
}

/* 
 * function deleteNative		: Deletes the native objects and frees the allocated memory.
 * param enc					: A pointer to the native object that does the encryption.
 * param dec					: A pointer to the native object that does the decryption.
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_midLayer_symmetricCrypto_encryption_OpenSSLEncWithIVAbs_deleteNative
  (JNIEnv *, jobject, jlong enc, jlong dec){
	  EVP_CIPHER_CTX_cleanup((EVP_CIPHER_CTX*)enc);
	  EVP_CIPHER_CTX_cleanup((EVP_CIPHER_CTX*)dec);
	  EVP_CIPHER_CTX_free((EVP_CIPHER_CTX*)enc);
	  EVP_CIPHER_CTX_free((EVP_CIPHER_CTX*)dec);
}

/* 
 * function setKey			: Initializes the CBC encryption  and decryption objects with a prp object and a key.
 * param enc				: A pointer to the native object that does the encryption.
 * param dec				: A pointer to the native object that does the decryption.
 * param prpName			: The name of the underlying prp object to use.
 * param key				: The bytes of the key to initialize the objects with.
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_midLayer_symmetricCrypto_encryption_OpenSSLCBCEncRandomIV_setKey
  (JNIEnv *env, jobject, jlong enc, jlong dec, jstring prpName, jbyteArray key){
	  //Convert the given data into c++ notation.
	  jbyte* keyBytes  = (jbyte*) env->GetByteArrayElements(key, 0);
	  const char* str = env->GetStringUTFChars(prpName, NULL);

	  //Create the requested block cipher according to the given prpName.
	  const EVP_CIPHER* cipher;
	  if(strncmp(str,"AES",3) == 0) {
		 
		  //In case the given prp name is AES, the actual object to use depends on the key size.
		  int len = env->GetArrayLength(key)*8; //number of bits in key.

		  switch(len)  {
				case 128: cipher = EVP_aes_128_cbc();
								   break;
				case 192: cipher = EVP_aes_192_cbc();
								   break;
				case 256: cipher = EVP_aes_256_cbc();
								   break;
				default: break;
		  }
	  } else if(strncmp(str,"TripleDES",9) == 0) {
		  
		  cipher = EVP_des_ede3_cbc();
	  }
	  
	  //Initialize the encryption objects with the key and the created cipher.
	  EVP_EncryptInit ((EVP_CIPHER_CTX *)enc, cipher, (unsigned char*)keyBytes, NULL);
	  EVP_DecryptInit ((EVP_CIPHER_CTX *)dec, cipher, (unsigned char*)keyBytes, NULL);
	  
	  //Set the padding scheme.
	  EVP_CIPHER_CTX_set_padding((EVP_CIPHER_CTX *)enc, 1);
	  EVP_CIPHER_CTX_set_padding((EVP_CIPHER_CTX *)dec, 1);

	  //Release the allocated memory.
	  env->ReleaseByteArrayElements(key, keyBytes, 0);
	  env->ReleaseStringUTFChars(prpName, str);
}

/* 
 * function setKey			: Initializes the CTR encryption and decryption objects with a prp object and a key.
 * param enc				: A pointer to the native object that does the encryption.
 * param dec				: A pointer to the native object that does the decryption.
 * param prpName			: The name of the underlying prp object to use.
 * param key				: The bytes of the key to initialize the objects with.
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_midLayer_symmetricCrypto_encryption_OpenSSLCTREncRandomIV_setKey
	(JNIEnv *env, jobject, jlong enc, jlong dec, jstring prpName, jbyteArray key){
	  //Convert the given data into c++ notation.
	  jbyte* keyBytes  = (jbyte*) env->GetByteArrayElements(key, 0);
	  const char* str = env->GetStringUTFChars(prpName, NULL);

	  //Create the requested block cipher according to the given prpName.
	  const EVP_CIPHER* cipher;
	  if(strncmp(str,"AES",3) == 0) {
		  
		   //In case the given prp name is AES, the actual object to use depends on the key size.
		  int len = env->GetArrayLength(key)*8; //number of bit in key.

		  switch(len)  {
				case 128: cipher = EVP_aes_128_ctr();
								   break;
				case 192: cipher = EVP_aes_192_ctr();
								   break;
				case 256: cipher = EVP_aes_256_ctr();
								   break;
				default: break;
		  }
	  } 
	  
	  //Initialize the encryption objects with the key.
	  EVP_EncryptInit ((EVP_CIPHER_CTX *)enc, cipher, (unsigned char*)keyBytes, NULL);
	  EVP_DecryptInit ((EVP_CIPHER_CTX *)dec, cipher, (unsigned char*)keyBytes, NULL);
	  
	  //Release the allocated memory.
	  env->ReleaseByteArrayElements(key, keyBytes, 0);
	  env->ReleaseStringUTFChars(prpName, str);
}
