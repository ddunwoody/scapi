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
 * Concrete padding class that implements the BitPadding padding scheme, but instead of adding 10...0 bits, it adds 10...0 bytes. <p>
 * Padding is performed as follows: a single "1" byte is appended to the array, 
 * and then "0" bytes are appended so that the length in bytes of
 * the padded message becomes the requested length.
 *  
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public final class BitPadding implements PaddingScheme {

	/**
	 * Default constructor
	 */
	public BitPadding(){
	//
	}
	
	/**
	 * Pads the given byte array with padSize bytes according to the BitPadding padding scheme, but instead of adding 10...0 bit, it adds 10...0 bytes. <p>
	 * The value of the first added byte is 1 and the values of the rest added bytes are 0.
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
		
		//creates an array of aligned size
		byte[] paddedArray = new byte[inputLen + padSize];
		
		//copies the given input to the beginning of the aligned array
		System.arraycopy(padInput, 0, paddedArray, 0, inputLen);
		//adds the first byte of the padding the byte that represent the byte 10000000
		paddedArray[inputLen] = (byte) 0x80;
		
		//decreases the number of bytes left to align
		padSize--;
		
		//adds zero bytes until reaches the required bytes 
		Integer zero = new Integer(0);
		for(int i=1; i<=padSize; i++){
			paddedArray[inputLen + i] = zero.byteValue();
		}
		return paddedArray;
	}

	/**
	 * Removes the padding from the given byte array.
	 * pseudo-code:
	 * 		1. Remove all the zero bytes until you get to a byte equal to 1. 
	 * 		2. remove the 1 byte.
	 * @param paddedInput array to remove the padding from
	 * @return the array without the padding
	 */
	@Override
	public byte[] removePad(byte[] paddedInput) {
		int i;
		//find the index of the first padding byte
		for(i = paddedInput.length-1; i>=0; i--){
			if (paddedInput[i] == (byte) 0x80){
				break;
			}
		}
		//copy the array without the padding to a new array and return it
		byte[] original = new byte[i];
		System.arraycopy(paddedInput, 0, original, 0, i);
		return original;
	}

}
