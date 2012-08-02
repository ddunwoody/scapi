/**
* This file is part of SCAPI.
* SCAPI is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
* SCAPI is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
* You should have received a copy of the GNU General Public License along with SCAPI.  If not, see <http://www.gnu.org/licenses/>.
*
* Any publication and/or code referring to and/or based on SCAPI must contain an appropriate citation to SCAPI, including a reference to http://crypto.cs.biu.ac.il/SCAPI.
*
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
*
*/
package edu.biu.scapi.paddings;

/**
 * Concrete padding class implements the BitPadding padding scheme, but instead of add 10...0 bit, we add 10...0 bytes. <p>
 * Padding is performed as follows: a single "1" byte is appended to the array, 
 * and then "0" bytes are appended so that the length in bytes of
 * the padded message becomes the requested length.
 *  
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class BitPadding implements PaddingScheme {

	/**
	 * Default constructor
	 */
	public BitPadding(){
	//
	}
	
	/**
	 * Pads the given byte array with padSize bytes according to BitPadding padding scheme, but instead of add 10...0 bit, we add 10...0 bytes. <p>
	 * The value of the first added byte is 1 and the values if the nest added bytes are 0.
	 * @param padInput array to pad
	 * @param padSize number of bytes to add to padInput array
	 * @return the padded array
	 */
	@Override
	public byte[] pad(byte[] padInput, int padSize) {
		
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
