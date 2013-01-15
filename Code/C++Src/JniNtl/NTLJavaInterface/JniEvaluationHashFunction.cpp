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
#include "stdafx.h"
#include "JniEvaluationHashFunction.h"
#include "EvaluationHashFunction.h"

JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_universalHash_EvaluationHashFunction_initHash
  (JNIEnv *env, jobject, jbyteArray key, jlong offset){


	  //first create dynamically the EvaluationHashFunction 
	  EvaluationHashFunction* evalHashPtr = new EvaluationHashFunction;

	  //declare a byte array in c++
	  jbyte *carr;

      //get to carr the elements of the input byte array data
	  carr = env->GetByteArrayElements(key, 0);

	  //invoke the init function 
	  evalHashPtr->init((unsigned char *)carr);

	  //make sure to release the memory created in c++. The JVM will not release it automatically.
	  //the hash class does not need this memory anymore since it already created the key as a GF2E element
	  env->ReleaseByteArrayElements(key,carr,0);

	  //return the created dynamic allocation of the evaluation hash object
	  return (jlong) evalHashPtr;

}


JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_universalHash_EvaluationHashFunction_computeFunction
  (JNIEnv *env, jobject, jlong evalHashObjectPtr , jbyteArray in, jbyteArray out, jint outOffset){

	  //cast the EvaluationHashFunction object
	  EvaluationHashFunction* evalHashPtr = (EvaluationHashFunction *)evalHashObjectPtr;

	   //declare a byte array in c++
	  jbyte *carrIn, *carrOut;

      //get to carr the elements of the input byte array data
	  carrIn = env->GetByteArrayElements(in, 0);
	  carrOut = env->GetByteArrayElements(out, 0);

	  //compute the function
	  evalHashPtr->computeFunction((unsigned char *)carrIn, 0, env->GetArrayLength(in), (unsigned char *)carrOut, outOffset);

	  //before releasing the c++ output array copy it to the java out array
	  //put the result of the final computation in the output array passed from java
	  env->SetByteArrayRegion(out, 0, env->GetArrayLength(out), (jbyte*)carrOut); 

	  //make sure to release the memory created in c++. The JVM will not release it automatically.
	  env->ReleaseByteArrayElements(in,carrIn,0);
	  env->ReleaseByteArrayElements(out,carrOut,0);

}
