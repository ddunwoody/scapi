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

#ifdef _WIN32
#include "stdafx.h"
#endif

#include <jni.h>
extern "C" {
#include <miracl.h>
}
#include <math.h>
#include "Utils.h"
#include "ECF2mPoint.h"

/* function createF2mPoint : This function creates a point of elliptic curve over F2m according to the accepted values
 * param m				  : pointer to mip
 * param xVal			  : x value of the point
 * param yVal			  : y value of the point
 * param validity	      : indicates if the point is valid for the current curve or not
 * return			      : A pointer to the created point.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_miracl_ECF2mPointMiracl_createF2mPoint
  (JNIEnv *env, jobject obj, jlong m, jbyteArray xVal, jbyteArray yVal){
	  /* convert the accepted parameters to MIRACL parameters*/
	  miracl* mip = (miracl*)m;
	  
	  /* create the point with x,y values */
	  epoint* p = epoint_init(mip);
	  big x = byteArrayToMiraclBig(env, mip, xVal);
	  big y = byteArrayToMiraclBig(env, mip, yVal);

	  bool valid = epoint2_set(mip, x, y, 0, p);

	  mirkill(x);
	  mirkill(y);

	  if (!valid) {
		 epoint_free(p);
		 return 0;
	  }
	  return (jlong) p; // return the point
}

/* function createF2mPointFromX : This function creates a point of elliptic curve over F2m according to the accepted values
 * param m						: pointer to mip
 * param xVal					: x value of the point
 * param validity				: indicates if the point is valid for the current curve or not
 * return						: A pointer to the created point.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_miracl_ECF2mPointMiracl_createF2mPointFromX
  (JNIEnv *env, jobject obj, jlong m, jbyteArray xVal, jbooleanArray validity){
	  /* convert the accepted parameters to MIRACL parameters*/
	  miracl* mip = (miracl*)m;
	  jboolean* valid = env->GetBooleanArrayElements(validity, 0);
	  
	   /* create the point with x,y values */
	  epoint* p = epoint_init(mip);
	  big x = byteArrayToMiraclBig(env, mip, xVal);

	  valid[0] = epoint2_set(mip, x, x, 1, p);

	  /* release the array */
	  env->ReleaseBooleanArrayElements(validity, valid, 0);
	  
	  mirkill(x);

	  return (jlong) p; // return the point
}

/* function createRandomF2mPoint : This function creates a random point of elliptic curve over F2m
 * param m						: pointer to mip
 * param pVal					: field's prime 
 * param validity				: indicate if the point was created correctly or not
 * return						: A pointer to the created point.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_miracl_ECF2mPointMiracl_createRandomF2mPoint
	(JNIEnv *env, jobject obj, jlong m, jint mod, jint seed, jbooleanArray validity){
	   /* convert the accepted parameters to MIRACL parameters*/
	   miracl* mip = (miracl*)m;
	   jboolean* valid = env->GetBooleanArrayElements(validity, 0);
	   int i;

	   //create the point
	   epoint* point = epoint_init(mip);
	   
	   /* choose randomly x,y values*/
	   int len = 2*mod;
	   big bigMod = mirvar(mip, 0);
	   big x = mirvar(mip, 0);

	   expb2(mip, mod, bigMod); //gets 2^mod
	   irand(mip, seed); //set seed to generate random numbers
	   for(i=0; i<len; i++){
		   bigrand(mip, bigMod, x); //get a random number in the field
		   if (epoint2_set(mip, x, x,1 ,point)==1){
			   //set the point with tthe chosen x, miracl choose y value according to this x
			   valid[0] = 1;
			   break; //stop the loop
		   }
	   }
	   
	   /* release the jni array */
	   env->ReleaseBooleanArrayElements(validity, valid, 0);
	  
	   mirkill(bigMod);
	   mirkill(x);
	   return (jlong)point; // return the point
}

/* function checkInfinityF2m : This function checks if this point is the infinity
 * param point					: point to check
 * return						: true if this point is fthe infinity, false otherwise
 */

JNIEXPORT jboolean JNICALL Java_edu_biu_scapi_primitives_dlog_miracl_ECF2mPointMiracl_checkInfinityF2m
  (JNIEnv *env, jobject obj, jlong point){

	  return point_at_infinity((epoint*)point);

}

/* function getXValue : This function return the x coordinate of the given point
 * param m			  : pointer to mip
 * param point		  : pointer to the point
 * return			  : the x coordinate of the given point
 */
JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_primitives_dlog_miracl_ECF2mPointMiracl_getXValueF2mPoint
  (JNIEnv *env, jobject obj, jlong m, jlong point){
	  /* convert the accepted parameters to MIRACL parameters*/
	  miracl* mip = (miracl*)m;

	  big x, y;
	  jbyteArray xBytes;
	  x= mirvar(mip, 0);
	  y= mirvar(mip, 0);

	  //get x, y values of the point
	  epoint2_get(mip, (epoint*)point, x, y);

	  xBytes =  miraclBigToJbyteArray(env, mip, x);
	 
	  mirkill(x);
	  mirkill(y);
	  //return the bytes of x
	  return xBytes;
}

/* function getYValue : This function return the y coordinate of the given point
 * param m			  : pointer to mip
 * param point		  : pointer to the point
 * return			  : the y coordinate of the given point
 */
JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_primitives_dlog_miracl_ECF2mPointMiracl_getYValueF2mPoint
  (JNIEnv * env, jobject obj, jlong m, jlong point){
	  /* convert the accepted parameters to MIRACL parameters*/
	  miracl* mip = (miracl*)m;

	  big x, y;
	  jbyteArray yBytes;
	  x= mirvar(mip, 0);
	  y= mirvar(mip, 0);

	  //get x, y values of the point
	  epoint2_get(mip, (epoint*)point, x, y);

	  yBytes =  miraclBigToJbyteArray(env, mip, y);
	 
	  mirkill(x);
	  mirkill(y);
	  //retur nthe bytes of x
	  return yBytes;
}

/* function deletePointFp : This function deletes point of elliptic curve over Fp
 * param p				  : pointer to elliptic curve point
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_dlog_miracl_ECF2mPointMiracl_deletePointF2m
  (JNIEnv *env, jobject obj, jlong p){
	  epoint_free((epoint*)p);
}
