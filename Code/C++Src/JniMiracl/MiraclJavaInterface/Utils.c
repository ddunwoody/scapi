#include "StdAfx.h"
#include "Utils.h"

#include <stdlib.h>

big byteArrayToMiraclBig(JNIEnv *env, miracl *mip, jbyteArray byteArrToConvert){
	  
	//get jbyte* from byteArrToConvert
	jbyte* pjbyte  = env->GetByteArrayElements(byteArrToConvert, 0);
	big result;

	result = mirvar(mip,0);  
	bytes_to_big(mip, env->GetArrayLength(byteArrToConvert), (char*)pjbyte, result);
	
	//release jbyte
	env ->ReleaseByteArrayElements(byteArrToConvert, pjbyte, 0);

	//return the Integer
	return result;
}

jbyteArray miraclBigToJbyteArray(JNIEnv *env, miracl *mip, big bigToConvert){
	/* miracl big number is a struct contains the number digits and the length.
	 * in order to convert a big number to a byteArray, we need to copy the digits and to add a byte contains the sign of the number.
	 * to do so, we need to allocate anough place - number of digits +1 byte represent the sign
	 */
	int size = (int)(bigToConvert->len&MR_OBITS)*(MIRACL/8)+1;
	char* bytesValue = (char*) calloc(size, sizeof(char));
	jbyteArray result;
	
	big_to_bytes(mip, size, bigToConvert, bytesValue, TRUE);
	
	//build jbyteArray from the byteArray
	result = env-> NewByteArray(size);
	
	env->SetByteArrayRegion(result, 0, size, (jbyte*)bytesValue);
	
	 //delete the allocated memory
	free(bytesValue);
	
	//return the jbyteArray
	return result;
}