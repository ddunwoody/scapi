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

// cryptopp includes
#include "integer.h"
#include "osrng.h"
#include "cryptlib.h"
#include "modarith.h"

// local includes
#include "TPElement.h"
#include "Utils.h"

using namespace std;
using namespace CryptoPP;
/*
 * function getPointerToElement		: This function accept an jbyteArray, convert it to Integer and return pointer to it.
 * param element					: The Integer
 * return jlong						: The pointer
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_trapdoorPermutation_cryptopp_CryptoPpTrapdoorElement_getPointerToElement
  (JNIEnv *env, jobject, jbyteArray element) {
	  Utils utils;

	  //convert to Integer and get pointer to it
	  Integer* pointerToEl = utils.jbyteArrayToCryptoPPIntegerPointer(env, element);

	  //return the pointer
	  return (jlong) pointerToEl;
}

/*
 * function getElement		: This function accept a pointer to Integer and return this Integer as jbyteArray
 * param element					: The Integer
 * return jlong						: The pointer
 */
JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_primitives_trapdoorPermutation_cryptopp_CryptoPpTrapdoorElement_getElement
  (JNIEnv *env, jobject, jlong pElement) {
	  Utils utils;

	  //convert to jbyteArray and return it
	  return utils.CryptoPPIntegerTojbyteArray(env, *((Integer*)pElement));
}

/*
 * function deleteElement		: This function accept a pointer to Integer and free the allocated memory for that Integer
 * param elPtr					: The pointer
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_trapdoorPermutation_cryptopp_CryptoPpTrapdoorElement_deleteElement
  (JNIEnv *env, jobject , jlong elPtr) {

	  //free the allocated memory
	  delete((Integer*) elPtr);
}

/*
 * function getPointerToRandomRSAElement	: This function create a random RSA element
 * param modN								: mod (N)
 * return jlong								: pointer to the random element
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_trapdoorPermutation_cryptopp_CryptoPpRSAElement_getPointerToRandomRSAElement
  (JNIEnv *env, jobject, jbyteArray modN) {
	  
	   //Random Number Generator
	  AutoSeededRandomPool rng;
	  Utils utils;
	  Integer randNumber;

	  //get the Integer value of mod(N)
	  Integer mod = utils.jbyteArrayToCryptoPPInteger(env, modN);
	  
	  //get a random value in the required range
	  randNumber.Randomize(rng, 1, mod-1);

	  //return pointer to the random element
	  return (jlong) utils.getPointerToInteger(randNumber);
}

/*
 * function getPointerToRandomRabinElement	: This function creates a random Rabin element
 * param modN								: mod (N)
 * return jlong								: pointer to the random element
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_trapdoorPermutation_cryptopp_CryptoPpRabinElement_getPointerToRandomRabinElement
  (JNIEnv *env, jobject, jbyteArray modN) {
	  
	  Utils utils;
	  Integer N = utils.jbyteArrayToCryptoPPInteger(env, modN);
	  ModularArithmetic modn(N);
	  AutoSeededRandomPool rng;
	  Integer *r;
	  int count = 1;
	  //The sampled number r also has to be such that GCD(r,N) = 1, tries again until it finds.
	  for(int i = 0; ; i++){
		  r = new Integer(rng, Integer::One(), N - Integer::One());
		  if(Integer::Gcd(*r, N) == 1){
			  break;
		  }
		  delete r;
	  }
	  

	  Integer result = modn.Square(*r);
	  delete r;	
	  //return pointer to the random Rabin element
	  return (jlong) utils.getPointerToInteger(result);
}
