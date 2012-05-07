#include "StdAfx.h"
#include "ECFpPoint.h"
#include <jni.h>
#include "Utils.h"
#include "miracl.h"
#include <stdio.h>

/* function createFpPoint : This function creates a point of elliptic curve over Fp according to the accepted values
 * param m				  : pointer to mip
 * param xVal			  : x value of the point
 * param yVal			  : y value of the point
 * param validity	      : indicates if the point is valid for the current curve or not
 * return			      : A pointer to the created point.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_miracl_ECFpPointMiracl_createFpPoint
  (JNIEnv *env, jobject obj, jlong m, jbyteArray xVal, jbyteArray yVal, jbooleanArray validity){
	  /* convert the accepted parameters to MIRACL parameters*/
	  miracl* mip = (miracl*)m;
	  jboolean* valid = env->GetBooleanArrayElements(validity, 0);
	  
	  /* create the point with x,y values */
	  epoint* p = epoint_init(mip);
	  big x = byteArrayToMiraclBig(env, mip, xVal);
	  big y = byteArrayToMiraclBig(env, mip, yVal);

	  valid[0] = epoint_set(mip, x, y, 0, p);
	  
	  /* release the array */
	  env->ReleaseBooleanArrayElements(validity, valid, 0);
	  
	  mirkill(x);
	  mirkill(y);

	  return (jlong) p; // return the point
	 
}

/* function createFpPointFromX	: This function creates a point of elliptic curve over Fp according to the accepted values
 * param m						: pointer to mip
 * param xVal					: x value of the point
 * param validity				: indicates if the point is valid for the current curve or not
 * return						: A pointer to the created point.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_miracl_ECFpPointMiracl_createFpPointFromX
  (JNIEnv *env, jobject obj, jlong m, jbyteArray xVal, jbooleanArray validity){
	  /* convert the accepted parameters to MIRACL parameters*/
	  miracl* mip = (miracl*)m;
	  jboolean* valid = env->GetBooleanArrayElements(validity, 0);
	  
	  /* create the point with x,y values */
	  epoint* p = epoint_init(mip);
	  big x = byteArrayToMiraclBig(env, mip, xVal);

	  valid[0] = epoint_set(mip, x, x, 1, p);
	  
	  /* release the array */
	  env->ReleaseBooleanArrayElements(validity, valid, 0);
	  
	  mirkill(x);

	  return (jlong) p; // return the point
	 
}

/* function createRandomFpPoint : This function creates a random point of elliptic curve over Fp
 * param m						: pointer to mip
 * param pVal					: field's prime 
 * param validity				: indicates if the point was created correctly or not
 * return						: A pointer to the created point.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_miracl_ECFpPointMiracl_createRandomFpPoint
  (JNIEnv *env, jobject obj, jlong m, jbyteArray pVal, jint seed, jbooleanArray validity){
	   /* convert the accepted parameters to MIRACL parameters*/
	   miracl* mip = (miracl*)m;
	   big p = byteArrayToMiraclBig(env, mip, pVal);
	   jboolean* valid = env->GetBooleanArrayElements(validity, 0);
	   int i;

	   //create the point
	   epoint* point = epoint_init(mip);
	   
	   /* choose randomly x,y values*/
	   int len = 2*(env->GetArrayLength(pVal));
	   big x = mirvar(mip, 0);

	   irand(mip, seed); //set seed to generate random numbers

	   for(i=0; i<len; i++){
		   
		   bigrand(mip, p, x); //get a random number in the field
		   if (epoint_x(mip, x)==1){ //test if the x value is valid
			   //set the point with the chosen x, miracl choose y value according to this x
			   valid[0] = epoint_set(mip, x, x,1 ,point);
			   break; //stop the loop
		   }
	   }
	   
	   /* release the jni array */
	   env->ReleaseBooleanArrayElements(validity, valid, 0);

	   mirkill(p);
	   mirkill(x);

	   return (jlong)point; // return the point
}

/* function checkInfinityFp : This function checks if this point is the infinity
 * param point					: point to check
 * return						: true if this point is fthe infinity, false otherwise
 */

JNIEXPORT jboolean JNICALL Java_edu_biu_scapi_primitives_dlog_miracl_ECFpPointMiracl_checkInfinityFp
  (JNIEnv * env, jobject obj, jlong point){

	  return point_at_infinity((epoint*)point);

}

/* function getXValue : This function return the x coordinate of the given point
 * param m			  : pointer to mip
 * param point		  : pointer to the point
 * return			  : the x coordinate of the given point
 */
JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_primitives_dlog_miracl_ECFpPointMiracl_getXValueFpPoint
  (JNIEnv *env, jobject obj, jlong m, jlong point){
	  /* convert the accepted parameters to MIRACL parameters*/
	  miracl* mip = (miracl*)m;
	  big x, y;
	  jbyteArray xBytes;

	  x= mirvar(mip, 0);
	  y= mirvar(mip, 0);

	  //get x, y values of the point
	  epoint_get(mip, (epoint*)point, x, y);

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
JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_primitives_dlog_miracl_ECFpPointMiracl_getYValueFpPoint
  (JNIEnv * env, jobject obj, jlong m, jlong point){
	  /* convert the accepted parameters to MIRACL parameters*/
	  miracl* mip = (miracl*)m;

	  big x, y;
	  jbyteArray yBytes;

	  x= mirvar(mip, 0);
	  y= mirvar(mip, 0);

	  //get x, y values of the point
	  epoint_get(mip, (epoint*)point, x, y);

	  yBytes =  miraclBigToJbyteArray(env, mip, y);
	 
	  mirkill(x);
	  mirkill(y);

	  //return the bytes of x
	  return yBytes;
}

/* function deletePointFp : This function deletes point of elliptic curve over Fp
 * param p				  : pointer to elliptic curve point
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_dlog_miracl_ECFpPointMiracl_deletePointFp
  (JNIEnv *env, jobject obj, jlong p){
	  epoint_free((epoint*)p);
}