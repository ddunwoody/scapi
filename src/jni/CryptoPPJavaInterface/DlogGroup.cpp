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

// cryptopp includes
#include "cryptlib.h"
#include "gfpcrypt.h"
#include "osrng.h"

// local includes
#include "DlogGroup.h"
#include "Utils.h"

using namespace CryptoPP;

/* function createDlogZp : This function creates a Dlog group over Zp and returns a pointer to the created Dlog.
 * param p				 : field size (prime)
 * param q				 : order of the group
 * param g				 : generator of the group
 * return			     : A pointer to the created Dlog.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_cryptopp_CryptoPpDlogZpSafePrime_createDlogZp
  (JNIEnv *env, jobject, jbyteArray p, jbyteArray q, jbyteArray possibleGenerator){
	  Utils utils;

	  //convert to Integer
	  Integer integerP = utils.jbyteArrayToCryptoPPInteger(env, p);
	  Integer integerQ = utils.jbyteArrayToCryptoPPInteger(env, q);
	  Integer integerXG = utils.jbyteArrayToCryptoPPInteger(env, possibleGenerator);

	  //create the Dlog group and initialise it with the size and generator
	  DL_GroupParameters_GFP_DefaultSafePrime * group = new DL_GroupParameters_GFP_DefaultSafePrime();
	  group->Initialize(integerP,  integerQ, integerXG);

	  return (jlong) group; //return pointer to the group
}

/* function createDlogZp : This function creates a Dlog group over Zp and returns a pointer to the created Dlog.
 * param numBits		 : p size
 * return			     : A pointer to the created Dlog.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_cryptopp_CryptoPpDlogZpSafePrime_createRandomDlogZp
  (JNIEnv *env, jobject, jint numBits){
	  Utils utils;

	  //Random Number Generator
	  AutoSeededRandomPool rng;

	  //create the Dlog group and initialise it with the size and generator
	  DL_GroupParameters_GFP_DefaultSafePrime * group = new DL_GroupParameters_GFP_DefaultSafePrime();
	  group->Initialize(rng, numBits);

	  return (jlong) group; //return pointer to the group
}

/* function getGenerator : This function return the group generator
 * param group			 : pointer to the group
 * return			     : A pointer to the Integer value of the generator
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_cryptopp_CryptoPpDlogZpSafePrime_getGenerator
  (JNIEnv *, jobject, jlong group){
	  Utils utils;

	  //get the generator
	  Integer gen = ((DL_GroupParameters_GFP_DefaultSafePrime*) group)->GetSubgroupGenerator();

	  return (jlong) utils.getPointerToInteger(gen); //return a pointer to the generator

}

/* function getP		 : This function return the modulus of the group
* param group			 : pointer to the group
 * return			     : A byteArray representing the modulus
 */
JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_primitives_dlog_cryptopp_CryptoPpDlogZpSafePrime_getP
  (JNIEnv *env, jobject, jlong group){
	  Utils utils;

	  //get the mod
	  Integer p = ((DL_GroupParameters_GFP_DefaultSafePrime*) group)->GetModulus();

	  //return a byteArray representing the modulus
	  return  utils.CryptoPPIntegerTojbyteArray(env, p); 
}

/* function getQ		 : This function return the order of the group
* param group			 : pointer to the group
 * return			     : A byteArray representing the order
 */
JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_primitives_dlog_cryptopp_CryptoPpDlogZpSafePrime_getQ
  (JNIEnv *env, jobject, jlong group){
	  Utils utils;

	  //get the mod
	  Integer q = ((DL_GroupParameters_GFP_DefaultSafePrime*) group)->GetSubgroupOrder();

	  //return a byteArray representing the modulus
	  return  utils.CryptoPPIntegerTojbyteArray(env, q); 
}

/* function inverseElement : This function return the inverse of the accepted element
 * param group			   : pointer to the group
 * param element		   : element to find inverse
 * return			       : A pointer to the inverse element.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_cryptopp_CryptoPpDlogZpSafePrime_inverseElement
  (JNIEnv *, jobject, jlong group, jlong element){
	  Utils utils;

	  Integer mod = ((DL_GroupParameters_GFP_DefaultSafePrime*) group)->GetModulus(); //get the field modulus
	  ModularArithmetic ma(mod); //create ModularArithmetic object with the modulus

	  // get the inverse 
	  Integer result = ma.MultiplicativeInverse( *(Integer*)element);

	  // get pointer to the result and return it
	  return (jlong)utils.getPointerToInteger(result);
}

/* function exponentiateElement : This function exponentiate the accepted element
 * param group			   : pointer to the group
 * param element		   : element to exponentiate
 * param exponent
 * return			       : A pointer to the result element.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_cryptopp_CryptoPpDlogZpSafePrime_exponentiateElement
  (JNIEnv *env, jobject, jlong group, jlong element, jbyteArray exponent){
	   Utils utils;

	  //convert the exponent to Integer
	  Integer integerExp = utils.jbyteArrayToCryptoPPInteger(env, exponent);

	  //exponentiate the element
	  Integer result = ((DL_GroupParameters_GFP_DefaultSafePrime*) group)->ExponentiateElement(*(Integer*) element, integerExp);

	  //get pointer to the result and return it
	  Integer* resultP = utils.getPointerToInteger(result);
	  return (jlong)resultP;
}

/* function multiplyElements : This function multiplies two elements
 * param group			   : pointer to the group
 * param element1		    
 * param element2
 * return			       : A pointer to the result element.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_cryptopp_CryptoPpDlogZpSafePrime_multiplyElements
  (JNIEnv *, jobject, jlong group, jlong element1, jlong element2){
	  Utils utils;

	  //multiply the element
	  Integer result = ((DL_GroupParameters_GFP_DefaultSafePrime*) group)->MultiplyElements(*(Integer*) element1, *(Integer*) element2);

	  //get pointer to the result and return it
	  Integer* resultP = utils.getPointerToInteger(result);
	  return (jlong)resultP;
}

/*
 */
JNIEXPORT jboolean JNICALL Java_edu_biu_scapi_primitives_dlog_cryptopp_CryptoPpDlogZpSafePrime_validateZpGroup
  (JNIEnv *, jobject, jlong group){
	  //Random Number Generator
	  AutoSeededRandomPool rng;

	  /* call to crypto++ function validate that checks if the group is valid. 
	   * it checks the validity of p, q, and the generator.
	   * 3 is the checking level - full validate.
	   */
	  return ((DL_GroupParameters_GFP_DefaultSafePrime*) group)->Validate(rng, 3);
	 
}

/* function validateZpGenerator : This function checks if the generator of the group is valid or not.
								  The generator is valid if it is an element in the group and if it is not the identity
 * param group					: pointer to the group
 * return						: true if the generator is valid. false, otherwise
 */
JNIEXPORT jboolean JNICALL Java_edu_biu_scapi_primitives_dlog_cryptopp_CryptoPpDlogZpSafePrime_validateZpGenerator
  (JNIEnv *, jobject, jlong group){
	  
	  //get the group generator
	  Integer g = ((DL_GroupParameters_GFP_DefaultSafePrime*) group)->GetSubgroupGenerator();
	 
	  /* call to a crypto++ function that checks the generator validity.
	   * 3 is the checking level (full check), g is the generator and 0 is instead of DL_FixedBasedPrecomputation object 
	   */
	  return ((DL_GroupParameters_GFP_DefaultSafePrime*) group)->ValidateElement(3, g, 0);

	  
}

/* function validateZpElement : This function checks if the given element is valid or not.
								An element is valid if it is in the range [1...p-1] and if element^q = 1
 * param group			      : pointer to the group
 * param element		      : the element to check
 * return			          : true if the element is valid. false, otherwise
 */
JNIEXPORT jboolean JNICALL Java_edu_biu_scapi_primitives_dlog_cryptopp_CryptoPpDlogZpSafePrime_validateZpElement
  (JNIEnv *, jobject, jlong group, jlong element){
	  Integer e;
	  
	  e = *(Integer*)element;
	 
	  /* if the element is the identity than it is valid. 
	   * The function validateElement of crypto++ return false if the element is 1 so we checked it outside.
	   */
	  if (e.Compare(1)==0)
		  return true;

	  /* call to a crypto++ function that checks the element validity.
	   * 3 is the checking level (full check), e is the element and 0 is instead of DL_FixedBasedPrecomputation object 
	   */
	  return ((DL_GroupParameters_GFP_DefaultSafePrime*) group)->ValidateElement(3, e, 0);

	 
}

/* function deleteDlogZp   : This function frees the allocated memory
 * param groupPtr		   : pointer to the group
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_dlog_cryptopp_CryptoPpDlogZpSafePrime_deleteDlogZp
  (JNIEnv *, jobject, jlong groupPtr){
	  //free the allocated memory
	  delete((DL_GroupParameters_GFP_DefaultSafePrime*) groupPtr);
}
