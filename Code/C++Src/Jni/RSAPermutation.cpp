#include "stdafx.h"
#include "RSAPermutation.h"
#include "rsa.h"
#include "cryptlib.h"
#include "Utils.h"
#include "osrng.h"
#include "rabin.h"
#include <iostream>

using namespace std;
using namespace CryptoPP;

/*
 * function initRSAWithNED  : This function initialize the RSA object with public key and private key
 * param tpPtr				: The pointer to the trapdoor permutation object 
 * param modulus			: modolus (n)
 * param pubExp				: pubic exponent (e)
 * param privExp			: private exponent (d)
 * return jlong				: pointer to the native object
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_trapdoorPermutation_cryptopp_CryptoPpRSAPermutation_initRSAWithPublicPrivate
  (JNIEnv *env, jobject, jbyteArray modulus, jbyteArray pubExp, jbyteArray privExp) {
	  
	  Integer n, e, d;
	  Utils utils;

	  // get the Integers values for the RSA permutation 
	  n = utils.jbyteArrayToCryptoPPInteger(env, modulus);
	  e = utils.jbyteArrayToCryptoPPInteger(env, pubExp);
	  d = utils.jbyteArrayToCryptoPPInteger(env, privExp);

	  //create pointer to InvertibleRSAFunction object
	  InvertibleRSAFunction* tpPtr = new InvertibleRSAFunction;

	  //initialize the trapdoor object with the RSA values
	  ((InvertibleRSAFunction *) tpPtr) -> Initialize(n, e, d);

	  return (jlong) tpPtr;
}

/*
 * function initRSAWithNED  : This function initialize the RSA object with public key and private crt key
 * param tpPtr				: The pointer to the trapdoor permutation object 
 * param modulus			: modolus (n)
 * param pubExp				: pubic exponent (e)
 * param privExp			: private exponent (d)
 * return jlong				: pointer to the native object
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_trapdoorPermutation_cryptopp_CryptoPpRSAPermutation_initRSAPublicPrivateCrt
  (JNIEnv *env , jobject, jbyteArray modulus, jbyteArray pubExp, jbyteArray privExp, jbyteArray prime1, 
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
	  InvertibleRSAFunction *tpPtr = new InvertibleRSAFunction;

	  //initialize the trapdoor object with the RSA values
	  ((InvertibleRSAFunction *) tpPtr) -> Initialize(n, e, d, p, q, dp, dq, u);

	  return (jlong) tpPtr;
}


/*
 * function initRSAWithNumBitsAndE  : This function initialize the RSA object with random values
 * param tpPtr						: The pointer to the trapdoor permutation object 
 * param numBits					: number of bits
 * param pubExp						: pubic exponent (e)
 * return jlong						: pointer to the native object
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_trapdoorPermutation_cryptopp_CryptoPpRSAPermutation_initRSARandomly
  (JNIEnv *env, jobject, jint numBits, jbyteArray pubExp) {
	  //Random Number Generator
	  AutoSeededRandomPool rng;
	  Utils utils;

	  //get the integer value of the public exponent
	  Integer e = utils.jbyteArrayToCryptoPPInteger(env, pubExp);

	  //create pointer to InvertibleRSAFunction object
	  InvertibleRSAFunction *tpPtr = new InvertibleRSAFunction;

	  //initialize the trapdoor object with the random values
	  ((InvertibleRSAFunction *) tpPtr) -> Initialize(rng, numBits, e);

	   return (jlong) tpPtr;
} 

/*
 * function initRSAWithNE   : This function initialize the RSA object with public key 
 * param tpPtr				: The pointer to the trapdoor permutation object 
 * param modulus			: modolus (n)
 * param pubExp				: pubic exponent (e)
 * return jlong				: pointer to the native object
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_trapdoorPermutation_cryptopp_CryptoPpRSAPermutation_initRSAPublic
  (JNIEnv *env, jobject, jbyteArray modulus, jbyteArray pubExp) {
	  Integer n, e;
	  Utils utils;

	  /* get the Integers values for the RSA permutation */
	  n = utils.jbyteArrayToCryptoPPInteger(env, modulus);
	  e = utils.jbyteArrayToCryptoPPInteger(env, pubExp);
	  
	  //create pointer to RSAFunction object
	  TrapdoorFunction* ptr = new RSAFunction; //assign RSAFunction to the pointer

	  //initialize the trapdoor object with the RSA values
	  ((RSAFunction *) ptr) -> Initialize(n, e);

	  return (jlong) ptr;
}

/*
 * function loadRSAName : This function return the name of the RSA trapdoor permutation
 * param ptr	        : The pointer to the RSA object 
 * return			    : The name of the trapdoor permutation.
 */
JNIEXPORT jstring JNICALL Java_edu_biu_scapi_primitives_trapdoorPermutation_cryptopp_CryptoPpRSAPermutation_loadRSAName
  (JNIEnv *env, jobject, jlong tpPtr) {
	  //get the RSA algorithm name
	  string ls =((RSA *) tpPtr) -> StaticAlgorithmName();

	  //return the name 
	  return env->NewStringUTF(ls.c_str());
}

/*
 * function getRSAModulus   : This function return the modulus of the current RSA permutation
 * param tpPtr				: The pointer to the trapdoor permutation object 
 * return jbyteArray		:the modulus as byte array
 */
JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_primitives_trapdoorPermutation_cryptopp_CryptoPpRSAPermutation_getRSAModulus
  (JNIEnv *env, jobject, jlong tpPtr) {
	  Utils utils;
	  
	  //get the mod from the tp
	  Integer mod = ((RSAFunction *) tpPtr) -> GetModulus();

	  //convert the mod to jbyteArray and return it
	  return utils.CryptoPPIntegerTojbyteArray(env, mod);
}

/*
 * function checkRSAValidity  : This function check if the element is valid for this RSA permutation 
 *								(if the number if between 1 to mod(N))
 * param tpPtr				  : The pointer to the trapdoor permutation object 
 * param value				  : The element to check
 * return boolean			  : true if valid, false if not
 */
JNIEXPORT jboolean JNICALL Java_edu_biu_scapi_primitives_trapdoorPermutation_cryptopp_CryptoPpRSAPermutation_checkRSAValidity
  (JNIEnv *env, jobject, jlong value, jlong tpPtr) {
	  Utils utils;
	  Integer iValue, iMod;

	  //get the Integer value of the element
	  iValue = *((Integer*) value);

	  //get the modulus
	  iMod = ((RSAFunction *) tpPtr) -> GetModulus();
	  bool valid = false;

	  //if the element is in the range of 1 to mod(N) return true
	  if ((iValue < iMod) && (iValue > 0))
		valid = true;
	  return valid;
}

/*
 * function computeRSA	: This function compute the RSA function on the accepted element
 * param tpPtr				: The pointer to the RSA object 
 * param element			: The element for the computation
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_trapdoorPermutation_cryptopp_CryptoPpRSAPermutation_computeRSA
  (JNIEnv *env, jobject, jlong tpPtr, jlong element) {
	  
	  Utils utils;

	  //get the Integer value for the computation
	  Integer x = *(Integer*) element;

	  //operate the compute
	  Integer result = ((RSAFunction *) tpPtr)-> ApplyFunction(*(Integer*) element);

	  //return the result as jbyteArray
	  return (jlong) utils.getPointerToInteger(result);
}

/*
 * function invertRSA   : This function invert the RSA permutation.
 * param tpPtr	        : The pointer to the RSA object 
 * param element		: The element to invert
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_trapdoorPermutation_cryptopp_CryptoPpRSAPermutation_invertRSA
  (JNIEnv *env, jobject, jlong tpPtr, jlong element) {
	  // Random Number Generator
	  AutoSeededRandomPool rng;
	  Utils utils;
	  
	  //get the Integer value to invert
	  Integer x = *(Integer*) element;

	  //operate the invert
	  Integer result = ((InvertibleRSAFunction *) tpPtr) -> CalculateInverse(rng, *(Integer*) element);

	  //return the result as jbyteArray
	  return (jlong) utils.getPointerToInteger(result);
}

/*
 * Delete the native object
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_trapdoorPermutation_cryptopp_CryptoPpTrapdoorPermutation_deleteRSA
	(JNIEnv *, jobject, jlong tpPtr) {
		delete((RSAFunction*) tpPtr);
}
