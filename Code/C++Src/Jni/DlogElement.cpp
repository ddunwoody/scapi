#include "stdafx.h"
#include "DlogElement.h"
#include "Utils.h"
#include "Integer.h"

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
	  delete((void*) elPtr);
}