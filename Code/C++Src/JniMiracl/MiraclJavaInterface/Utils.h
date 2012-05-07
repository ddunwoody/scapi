#include "jni.h"
#include "miracl.h"

big byteArrayToMiraclBig(JNIEnv *env, miracl* mip, jbyteArray byteArrToConvert);
jbyteArray miraclBigToJbyteArray(JNIEnv *env, miracl *mip, big bigToConvert);
