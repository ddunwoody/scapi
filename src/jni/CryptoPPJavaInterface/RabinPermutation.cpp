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
#include "rabin.h"
#include "cryptlib.h"
#include "osrng.h"
#include "nbtheory.h"

// local includes
#include "RabinPermutation.h"
#include "Utils.h"

using namespace std;
using namespace CryptoPP;

/*
 * function initRabinAll    : This function initialize the Rabin object with public key and private key
 * param tpPtr				: The pointer to the trapdoor permutation object 
 * param mod    			: modolus (n) 
 * param r					: quadratic residue mod prime 1
 * param s					: quadratic residue mod prime 2
 * param p					: prime 1
 * param q					: prime 2
 * param u					: inverse of p mod (q)
 * return jlong				: pointer to the native object
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_trapdoorPermutation_cryptopp_CryptoPpRabinPermutation_initRabinPublicPrivate
  (JNIEnv *env, jobject, jbyteArray mod, jbyteArray r, jbyteArray s, jbyteArray p , jbyteArray q, jbyteArray u) {
	  Utils utils;
	  Integer modN, m_r, m_s, m_p, m_q, m_u;

	  /* get the Integers values for the Rabin permutation */
	  modN=utils.jbyteArrayToCryptoPPInteger(env, mod);
	  m_r=utils.jbyteArrayToCryptoPPInteger(env, r);
	  m_s=utils.jbyteArrayToCryptoPPInteger(env, s);
	  m_p=utils.jbyteArrayToCryptoPPInteger(env, p);
	  m_q=utils.jbyteArrayToCryptoPPInteger(env, q);
	  m_u=utils.jbyteArrayToCryptoPPInteger(env, u);

	  //create pointer to InvertibleRabinFunction object
	  TrapdoorFunction *tpPtr = new InvertibleRabinFunction;

	  //initialize the Rabin object with the parameters
	  ((InvertibleRabinFunction *) tpPtr) -> Initialize(modN, m_r, m_s, m_p, m_q, m_u);

	  return (jlong) tpPtr; // return the pointer

}

/*
 * function initRabinNRS    : This function initialize the Rabin object with public key 
 * param tpPtr				: The pointer to the trapdoor permutation object 
 * param mod    			: modolus (n) 
 * param r					: quadratic residue mod prime 1
 * param s					: quadratic residue mod prime 2
 * return jlong				: pointer to the native object
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_trapdoorPermutation_cryptopp_CryptoPpRabinPermutation_initRabinPublic
  (JNIEnv *env, jobject, jbyteArray n, jbyteArray r, jbyteArray s) {
	  Utils utils;
	  Integer m_n, m_r, m_s;

	  // get the Integers values for the Rabin permutation
	  m_n=utils.jbyteArrayToCryptoPPInteger(env, n);
	  m_r=utils.jbyteArrayToCryptoPPInteger(env, r);
	  m_s=utils.jbyteArrayToCryptoPPInteger(env, s);
	 
	  //create pointer to RabinFunction object
	  TrapdoorFunction* tpPtr =  new RabinFunction;  //assign RSAFunction to the pointer

	  //initialize the Rabin object with the parameters
	  ((RabinFunction *) tpPtr) -> Initialize(m_n, m_r, m_s);

	  return (jlong) tpPtr; // return the pointer
}

/*
 * function initRabinKeySize    : This function initialize the Rabin object with random values
 * param tpPtr					: The pointer to the trapdoor permutation object 
 * param numBits				: Number of bits
  * return jlong				: pointer to the native object
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_trapdoorPermutation_cryptopp_CryptoPpRabinPermutation_initRabinRandomly
  (JNIEnv * env, jobject, jint numBits) {
	  //Random Number Generator
	  AutoSeededRandomPool rng;
	  
	  //create pointer to InvertibleRabinFunction object
	  TrapdoorFunction *tpPtr = new InvertibleRabinFunction;

	  //initialize the trapdoor object with the random values
	  ((InvertibleRabinFunction *) tpPtr) -> Initialize(rng, numBits);

	  return (jlong) tpPtr; // return the pointer
}

/*
 * function loadRabinName : This function return the name of the Rabin trapdoor permutation
 * param ptr	          : The pointer to the Rabin object 
 * return			      : The name of the trapdoor permutation.
 */
JNIEXPORT jstring JNICALL Java_edu_biu_scapi_primitives_trapdoorPermutation_cryptopp_CryptoPpRabinPermutation_loadRabinName
  (JNIEnv *env, jobject, jlong tpPtr) {
	  //get the Rabin algorithm name
	  string ls =((Rabin *) tpPtr) -> StaticAlgorithmName();

	  //return the name 
	  return env->NewStringUTF(ls.c_str());
}

/*
 * function getRabinModulus		: This function return the modulus of the current Rabin permutation
 * param tpPtr					: The pointer to the trapdoor permutation object 
 * return jbyteArray			: The modulus as byte array
 */
JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_primitives_trapdoorPermutation_cryptopp_CryptoPpRabinPermutation_getRabinModulus
  (JNIEnv *env, jobject, jlong tpPtr) {
	  Utils utils;
	  Integer mod;

	  //get ghe mod from the tp
	  mod = ((InvertibleRabinFunction *) tpPtr) -> GetModulus(); 

	  //convert the mod to jbyteArray and return it
	  return utils.CryptoPPIntegerTojbyteArray(env, mod);
}

/*
 * function getPrime1						: This function returns the prime 1 (p) of the current Rabin permutation
 * param tpPtr								: The pointer to the trapdoor permutation object 
 * return jbyteArray						: The modulus as byte array
 */
JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_primitives_trapdoorPermutation_cryptopp_CryptoPpRabinPermutation_getPrime1
  (JNIEnv *env, jobject, jlong tpPtr){
	   Utils utils;
	  Integer r;

	  //get the value from the tp
	  r = ((InvertibleRabinFunction *) tpPtr) ->  GetPrime1();

	  //convert the value to jbyteArray and return it
	  return utils.CryptoPPIntegerTojbyteArray(env, r);
}

/*
 * function getPrime2						: This function returns the prime 2 (q) of the current Rabin permutation
 * param tpPtr								: The pointer to the trapdoor permutation object 
 * return jbyteArray						: The modulus as byte array
 */
JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_primitives_trapdoorPermutation_cryptopp_CryptoPpRabinPermutation_getPrime2
  (JNIEnv *env, jobject, jlong tpPtr){
	   Utils utils;
	  Integer r;

	  //get the value from the tp
	  r = ((InvertibleRabinFunction *) tpPtr) ->  GetPrime2();

	  //convert the value to jbyteArray and return it
	  return utils.CryptoPPIntegerTojbyteArray(env, r);
}

/*
 * function getinversePModQ						: This function return the inverse of p mod q of the current Rabin permutation
 * param tpPtr									: The pointer to the trapdoor permutation object 
 * return jbyteArray							: The modulus as byte array
 */
JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_primitives_trapdoorPermutation_cryptopp_CryptoPpRabinPermutation_getinversePModQ
  (JNIEnv *env, jobject, jlong tpPtr){
	   Utils utils;
	  Integer r;

	  //get the value from the tp
	  r = ((InvertibleRabinFunction *) tpPtr) -> GetMultiplicativeInverseOfPrime2ModPrime1();

	  //convert the value to jbyteArray and return it
	  return utils.CryptoPPIntegerTojbyteArray(env, r);
}

/*
 * function getQuadraticResidueModPrime1		: This function return the quadratic residue mod prime1 of the current Rabin permutation
 * param tpPtr									: The pointer to the trapdoor permutation object 
 * return jbyteArray							: The modulus as byte array
 */
JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_primitives_trapdoorPermutation_cryptopp_CryptoPpRabinPermutation_getQuadraticResidueModPrime1
  (JNIEnv *env, jobject, jlong tpPtr){
	  Utils utils;
	  Integer r;

	  //get the value from the tp
	  r = ((InvertibleRabinFunction *) tpPtr) ->  GetQuadraticResidueModPrime1();

	  //convert the value to jbyteArray and return it
	  return utils.CryptoPPIntegerTojbyteArray(env, r);
}

/*
 * function getQuadraticResidueModPrime2		: This function return the quadratic residue mod prime2 of the current Rabin permutation
 * param tpPtr									: The pointer to the trapdoor permutation object 
 * return jbyteArray							: The modulus as byte array
 */
JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_primitives_trapdoorPermutation_cryptopp_CryptoPpRabinPermutation_getQuadraticResidueModPrime2
  (JNIEnv *env, jobject, jlong tpPtr){
	  Utils utils;
	  Integer s;

	  //get ghe value from the tp
	  s = ((InvertibleRabinFunction *) tpPtr) ->  GetQuadraticResidueModPrime2();

	  //convert the value to jbyteArray and return it
	  return utils.CryptoPPIntegerTojbyteArray(env, s);
}

/*
 * function checkRabinValidity	  : This function check if the element is valid for this Rabin permutation 
 *								    (if the number if between 1 to mod(N))
 * param tpPtr					  : The pointer to the trapdoor permutation object 
 * param value					  : The element to check
 * return boolean				  : True if valid, false if not
 */
JNIEXPORT jboolean JNICALL Java_edu_biu_scapi_primitives_trapdoorPermutation_cryptopp_CryptoPpRabinPermutation_checkRabinValidity
  (JNIEnv *env, jobject, jlong pValue, jlong tpPtr) {
	Utils utils;
	Integer value, mod, p, q, square;
	
	//get the Integer value of the element
	value = *((Integer*) pValue);

	//get mod(N), p, q
	mod = ((RabinFunction *) tpPtr) -> GetModulus();
	p = ((InvertibleRabinFunction *) tpPtr) -> GetPrime1();
	q = ((InvertibleRabinFunction *) tpPtr) -> GetPrime2();
	 
	//check validity
	if ((Jacobi(value%p, p) == 1) && (Jacobi(value%q, q) == 1))
	return true;
	  
	return false;




	
}

/*
 * function computeRabin	: This function compute the Rabin function on the accepted element
 * param tpPtr				: The pointer to the Rabin object 
 * param element			: The element for the computation
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_trapdoorPermutation_cryptopp_CryptoPpRabinPermutation_computeRabin
  (JNIEnv *env, jobject, jlong tpPtr, jlong element) {
	  
	  Utils utils;

	  //get the Integer value for the computation
	  Integer x = *(Integer*) element;

	  Integer mod = ((RabinFunction *) tpPtr) -> GetModulus();
	  
	  ((RabinFunction *) tpPtr) -> DoQuickSanityCheck();

	  //compute
	  Integer result = x.Squared()%mod;

	  //return the result as jbyteArray
	  return (jlong) utils.getPointerToInteger(result);
}

/*
 * function invertRabin		: This function invert the Rabin permutation
 * param tpPtr				: The pointer to the Rabin object 
 * param element			: The element to invert
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_trapdoorPermutation_cryptopp_CryptoPpRabinPermutation_invertRabin
  (JNIEnv *env, jobject, jlong tpPtr, jlong element) {
	  // Random Number Generator
	  AutoSeededRandomPool rng;
	  Utils utils;

	  //get the Integer value to invert
	  Integer x = *(Integer*) element;

	
	  //invert
	  ((InvertibleRabinFunction *) tpPtr) ->DoQuickSanityCheck();
	  Integer mod = ((InvertibleRabinFunction *) tpPtr) -> GetModulus();
	  ModularArithmetic modn(mod);
	  Integer p = ((InvertibleRabinFunction *) tpPtr)->GetPrime1();
	  Integer q = ((InvertibleRabinFunction *) tpPtr)->GetPrime2();
	  Integer cp=x % p;
	  Integer cq=x % q;
	  cp = ModularSquareRoot(cp, p);
	  cq = ModularSquareRoot(cq, q);

	  Integer v =p.InverseMod(q);
      Integer u = ((InvertibleRabinFunction *) tpPtr)->GetMultiplicativeInverseOfPrime2ModPrime1();

	  Integer onep = modn.Multiply(u,q);
 
	  Integer oneq = modn.Multiply(v,p);
	  
 	  Integer outp1 = modn.Multiply(onep,cp);
      Integer outp2 = modn.Multiply(onep,p-cp);
      Integer outq1 = modn.Multiply(oneq,cq);
 
	  Integer outq2 = modn.Multiply(oneq,q-cq);
 
	  Integer out = (outp1 + outq1)% mod;
      if ((Jacobi(out%p, p) == 1) && (Jacobi(out%q, q) == 1)){
 
		return (jlong) utils.getPointerToInteger(out);
	  }
	  
	  out = (outp1 + outq2)%mod;
      if ((Jacobi(out%p, p) == 1) && (Jacobi(out%q, q) == 1))
 		return (jlong) utils.getPointerToInteger(out);
	  
	  out = (outp2 + outq1)%mod;
	  if ((Jacobi(out%p, p) == 1) && (Jacobi(out%q, q) == 1))
		  return (jlong) utils.getPointerToInteger(out);
	  
	  out = (outp2 + outq2)%mod;
	  if ((Jacobi(out%p, p) == 1) && (Jacobi(out%q, q) == 1))
		  return (jlong) utils.getPointerToInteger(out);
 
	  //If none of the above cases are true then retun a pointer to the Integer 0.
	  out = 0;
	  return (jlong) utils.getPointerToInteger(out);	

}

/*
 * Delete the native object
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_trapdoorPermutation_cryptopp_CryptoPpTrapdoorPermutation_deleteRabin
	(JNIEnv *, jobject, jlong tpPtr) {
		delete((RabinFunction*) tpPtr);
}
