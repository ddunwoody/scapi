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

// visual studio precompiled headers
#include "stdafx.h"

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
