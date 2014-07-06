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


package edu.biu.scapi.primitives.hash.cryptopp;

import edu.biu.scapi.primitives.hash.CryptographicHash;

/**
 * A general adapter class of hash for Crypto++. <p>
 * This class implements all the functionality by passing requests to the adaptee c++ abstract class HashTransformation of crypto++ using the JNI dll. 
 * A concrete hash function such as SHA1 represented by the class CryptoPpSHA1 only passes the name of the hash in the constructor 
 * to this base class. 
 * Since the underlying library is written in a native language we use the JNI architecture.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 *
 */
public abstract class CryptoPpHash implements CryptographicHash {

	protected long collHashPtr; //pointer to the native hash object
	
	//native functions. These functions are implemented in a c++ dll using JNI that we load. For secure coding always
	//declare native functions as private and wrap them by a java function.
	
	//creates a hash and returns the pointer. This pointer will be passed to all the other functions 
	//so the created hash object will be used. This is due to the lack of OOD of JNI and thus the 
	//created pointer must be passed each time.
	private native long createHash(String hashName);
	
	//returns crypto++ name of the hash
	private native String algName(long ptr);
	
	//updates the message to the hash
	private native void updateHash(long ptr, byte[] input, long len);
	
	//finishes the hash computation
	private native void finalHash(long ptr, byte[] output);
	
	//returns the size of the hashed msg
	private native int getDigestSize(long ptr);
	
	//deletes the created pointer.
	private native void deleteHash(long ptr);
	
	
	/**
	 * Constructs the related pointer of the underlying crypto++ hash.
	 * @param hashName - the name of the hash. This will be passed to the jni dll function createHash so it will know
	 * 					 which hash to create.
	 */
	public CryptoPpHash(String hashName) {
		
		
		//instantiates a hash object in crypto++. Remember to delete it using the finalize method.
		//we keep a pointer to the created hash object in c++.
		collHashPtr = createHash(hashName);
		
	} 
	
	/**
	 * @return the algorithm name taken from Crypto++
	 */
	public String getAlgorithmName() {
		
		//gets the algorithm name as crypto++ call it
		return algName(collHashPtr);
	}
	
	/**
	 * Adds the byte array to the existing message to hash. 
	 * @param in input byte array
	 * @param inOffset the offset within the byte array
	 * @param inLen the length. The number of bytes to take after the offset
	 * */
	public void update(byte[] in, int inOffset, int inLen) {
		
		//checks that the offset and length are correct
		if ((inOffset > in.length) || (inOffset+inLen > in.length) || (inOffset<0)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given input buffer");
		}
		
		if (inLen < 0){
			throw new NegativeArraySizeException("wrong length for the given input buffer");
		}
		
		if (inLen == 0){
			throw new ArrayIndexOutOfBoundsException("wrong length for the given input buffer");
		}
		
		//the dll function does the update from offset 0.
		//if the given offset is greater than 0, copies the relevant bytes to a new array and send it to the dll function.
		if (inOffset>0){
			byte[] input = new byte[inLen];
			System.arraycopy(in, inOffset, input, 0, inLen);
			//calls the native function
			updateHash(collHashPtr, input, inLen);
		}else {
		
			//if the offset is 0 - calls the native function with the given array
			updateHash(collHashPtr, in, inLen);
		}
	}

	/** 
	 * Completes the hash computation and puts the result in the out array.
	 * @param out the output in byte array
	 * @param outOffset the offset which to put the result bytes from
	 */
	public void hashFinal(byte[] out, int outOffset){
		
		//checks that the offset and length are correct
		if ((outOffset > out.length) || (outOffset+getHashedMsgSize() > out.length) || (outOffset<0)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given output buffer");
		}
		
		//if the offset is greater than 0 - puts the result in a new array and copies it to the out array starting at the outOffset
		if (outOffset>0){
			int length = getDigestSize(collHashPtr);
			byte[] tempOut = new byte[length];
			//calls the native function finalHash with the temp array
			finalHash(collHashPtr, tempOut);
			//copies the hash result to the out array in the right place
			System.arraycopy(tempOut, 0, out, outOffset, length);
			
		}else{
			//calls the native function final. 
			finalHash(collHashPtr, out);
		}
		

	}

	/** 
	 * @return the size of the hashed massage in bytes
	 */
	public int getHashedMsgSize() {
		
		//calls the native function
		return getDigestSize(collHashPtr);
	}
	
	
	/**
	 * Deletes the related collision resistant hash object
	 */
	protected void finalize() throws Throwable {
		
		//deletes from the dll the dynamic allocation of the hash.
		deleteHash(collHashPtr);
		
		super.finalize();
	}
	
	 static {
		 
		 //loads the crypto++ jni dll
		 System.loadLibrary("CryptoPPJavaInterface");
	 }

}
