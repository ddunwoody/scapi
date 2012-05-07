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
