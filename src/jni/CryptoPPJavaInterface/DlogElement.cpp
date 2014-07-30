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
#include "integer.h"

// local includes
#include "DlogElement.h"
#include "Utils.h"

/* function getPointerToElement : This function gets an element as byte array, turn it to Integer and return pointer to it
 * param element			: byte array
 * return			       : A pointer Integer represent the byteArray.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_cryptopp_ZpSafePrimeElementCryptoPp_getPointerToElement
  (JNIEnv *env, jobject, jbyteArray element){
	  Utils utils;

	  //convert to Integer and get pointer to it
	  Integer* pointerToEl = utils.jbyteArrayToCryptoPPIntegerPointer(env, element);

	  //return the pointer
	  return (jlong) pointerToEl;
}

/* function getElement : This function gets pointer to Integer and return it as byteArray
 * param element	   : pointer to Integer
 * return			   : byteArray represent the Integer
 */
JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_primitives_dlog_cryptopp_ZpSafePrimeElementCryptoPp_getElement
  (JNIEnv *env, jobject, jlong element){
	  Utils utils;

	  //convert to jbyteArray and return it
	  return utils.CryptoPPIntegerTojbyteArray(env, *((Integer*)element));
}

/* function deleteElement : This function gets pointer to Integer and delete it
 * param element	   : pointer to Integer
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_dlog_cryptopp_ZpSafePrimeElementCryptoPp_deleteElement
  (JNIEnv *, jobject, jlong elPtr){
	   //free the allocated memory
	  delete((Integer*) elPtr);
}
