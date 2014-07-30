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
#include <string>

// java jni includes
#include "jni.h"

// cryptopp includes
#include "sha.h"
#include "cryptlib.h"

// local includes
#include "CollisionResistantHash.h"

using namespace std;
using namespace CryptoPP;



/* function createHash : This function creates a hash and returns a pointer to the created hash. The function 
 * param hashName	   : The name of the hash we wish to create
 * return			   : A pointer to the created hash.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_hash_cryptopp_CryptoPpHash_createHash
  (JNIEnv *env, jobject, jstring hashName){

	HashTransformation *hashPtr = NULL;

	//get the string from java
	const char* str = env->GetStringUTFChars( hashName, NULL );

	//supports all of the SHA hashes. Get the name of the required hash and instanciate that hash.
	if(strcmp (str,"SHA1") == 0)
		hashPtr = new SHA1;
	else if(strcmp (str,"SHA224") == 0)
		hashPtr = new SHA224;
	else if(strcmp (str,"SHA256") == 0)
		hashPtr = new SHA256;
	else if(strcmp (str,"SHA384") == 0)
		hashPtr = new SHA384;
	else if(strcmp (str,"SHA512") == 0)
		hashPtr = new SHA512;

	env->ReleaseStringUTFChars(hashName, str);
	//return a pointer to the created hash.
	return (jlong)hashPtr;

}


/* function algName : This function gets the name of the hash function of the passed pointer to hash 
 * param hashPtr	: The actual hash object pointer to get the name from
 * return			: The name of the passed hash algorithm
 */
JNIEXPORT jstring JNICALL Java_edu_biu_scapi_primitives_hash_cryptopp_CryptoPpHash_algName
(JNIEnv *env, jobject, jlong hashPtr){

	//cast to HashTransformation wich is the base class of all hash function. 
	//the function AlgorithmName is defined there (actually in a base class of it)
	string shaName = ((HashTransformation *)hashPtr)->AlgorithmName();

	//return a string that Java can understand with the nama of the algorithm.
	return env->NewStringUTF(shaName.c_str());
}


/* function updateHash : This function updates the hash function with the byte array data
 * param hashPtr	   : The actual hash object pointer to update
 * param data		   : the byte array to translate to c++ and update the hash
 * param len		   : the length of the byte array
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_hash_cryptopp_CryptoPpHash_updateHash
(JNIEnv *env, jobject, jlong hashPtr, jbyteArray data, jlong len){

	//declare a byte array in c++
	jbyte *carr;

	//get to carr the elements of the input byte array data
	carr = env->GetByteArrayElements(data, 0);

	//invoke the update function after casting to HashTransformation that defines this function for all the derived hash
	//algorithms to implement
	((HashTransformation *)hashPtr)->Update((const byte *)carr, len);

	//make sure to release the memory created in c++. The JVM will not release it automatically.
	env->ReleaseByteArrayElements(data,carr,0);
}

/* function finalHash : This function completes the hash computation
 * param hashPtr	   : The actual hash object pointer 
 * param input		   : the byte array to put the result in
 * param size		   : the length of the byte array. This will be different for different hash functions
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_hash_cryptopp_CryptoPpHash_finalHash
(JNIEnv *env, jobject, jlong hashPtr, jbyteArray output){

	HashTransformation *localHashPtr = (HashTransformation *)hashPtr;

	//allocate a new byte array with the size of the specific hash algorithm.
	byte *ret = new byte[localHashPtr->DigestSize()]; 

	//perform the final function
	localHashPtr->Final(ret);

	//put the result of the final computation in the output array passed from java
	env->SetByteArrayRegion(output, 0, localHashPtr->DigestSize(), (jbyte*)ret); 

	//make sure to release the dynamically allocated memory. Will not be deleted by the JVM.
	delete ret;


}


JNIEXPORT jint JNICALL Java_edu_biu_scapi_primitives_hash_cryptopp_CryptoPpHash_getDigestSize
  (JNIEnv *, jobject, jlong hashPtr){

	  HashTransformation *localHashPtr = (HashTransformation *)hashPtr;
	  return (jint) localHashPtr->DigestSize();
}



/* function deleteHash : This function deletes the hash dynamically allocated pointer that was created in c++. This
 *						 memory allocation will not be deleted by the JVM.
 * param hashPtr	   : The actual hash object pointer 
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_hash_cryptopp_CryptoPpHash_deleteHash
(JNIEnv *, jobject, jlong hashPtr){
	delete((HashTransformation *) hashPtr);
}
