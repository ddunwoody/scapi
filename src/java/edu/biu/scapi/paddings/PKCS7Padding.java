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


package edu.biu.scapi.paddings;

/**
 * Concrete padding class implements the PKCS7 padding algorithm:
 * the input shall be padded at the trailing end with k-(lth mod k) octets all having value k-(lth mod k), where lth is
 * the length of the input. In other words, the input is padded at the trailing end with one of the following strings:
 *                01 -- if lth mod k = k-1
 *                02 02 -- if lth mod k = k-2
 *                    .
 *                    .
 *                    .
 *		          k k ... k k -- if lth mod k = 0
 *
 * This padding method is well defined if and only if k is less than 256.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public final class PKCS7Padding implements PaddingScheme {

	/**
	 * Default constructor
	 */
	public PKCS7Padding(){
		//
	}
	
	/**
	 * Pads the given byte array with padSize bytes according to PKCS7 padding scheme. <p>
	 * The value of each added byte is the number of bytes that are added, 
	 * i.e. N bytes, each of value N are added.
	 * @param padInput array to pad
	 * @param padSize number of bytes to add to padInput array
	 * @return the padded array
	 */
	@Override
	public byte[] pad(byte[] padInput, int padSize) {
		if (padSize <= 0){
			throw new IllegalArgumentException("padSize must be a positive number");
		}
		int inputLen = padInput.length;
		
		//byte value to put in each padded byte
		byte padNum = (byte) padSize;
		
		//creates an array of aligned size
		byte[] paddedArray = new byte[padInput.length + padSize];
		
		//copies the given input to the beginning of the aligned array
		System.arraycopy(padInput, 0, paddedArray, 0, padInput.length);
		
		//add padSize bytes with the byte value of the number of bytes to add
		for(int i=0; i<padSize; i++){
			paddedArray[inputLen + i] = padNum;
		}
		return paddedArray;
	}

	/**
	 * Removes the padding from the given byte array according to PKCS7 padding scheme.
	 * @param paddedInput array to remove the padding from
	 * @return the array without the padding
	 */
	@Override
	public byte[] removePad(byte[] paddedInput) {
		//get the number of padding bytes
		int numPadBytes = paddedInput[paddedInput.length-1];
		//size of the original array
		int originalSize = paddedInput.length - numPadBytes;
		
		//copy the array without the padding to a new array and return it
		byte[] original = new byte[originalSize];
		System.arraycopy(paddedInput, 0, original, 0, originalSize);
		return original;
	}

}
