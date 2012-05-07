#include "stdafx.h"
#include "TPElement.h"
#include "Utils.h"
#include <iostream>
#include "Integer.h"
#include "osrng.h"

using namespace std;

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
	  delete((void*) elPtr);
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
 * function getPointerToRandomRabinElement	: This function create a random Rabin element
 * param modN								: mod (N)
 * return jlong								: pointer to the random element
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_trapdoorPermutation_cryptopp_CryptoPpRabinElement_getPointerToRandomRabinElement
  (JNIEnv *env, jobject, jbyteArray modN) {
	  
	   //Random Number Generator
	  AutoSeededRandomPool rng;
	  Utils utils;
	  Integer randNumber;

	  //get the Integer value of mod(N)
	  Integer mod = utils.jbyteArrayToCryptoPPInteger(env, modN);
	  
	  //get a random value in the required range
	  randNumber.Randomize(rng, 1, mod-1);
	  //get the power of the random element
	  Integer pow = randNumber.Times(randNumber).Modulo(mod);
	  
	  //return pointer to the power element
	  return (jlong) utils.getPointerToInteger(pow);
}
