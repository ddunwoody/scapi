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
package edu.biu.scapi.primitives.trapdoorPermutation.cryptopp;

import java.math.BigInteger;

import edu.biu.scapi.primitives.trapdoorPermutation.TPElement;

/**
 * This class implements some common functionality of the wrappers of crypto++ trapdoor elements.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public abstract class CryptoPpTrapdoorElement implements TPElement{
	/* pointer to the CryptoPP::Integer.
	 * We save the pointer to an CryptoPP::Integer object to avoid unnecessary conversions 
	 * back and force when computing and inverting.
	 */
	protected long pointerToInteger; 
	
	//native functions. These functions are implemented in CryptoPpJavaInterface dll using the JNI tool.
	
	//returns pointer to the native object
	protected native long getPointerToElement(byte[] element);
	//returns the value of the native object
	protected native byte[] getElement(long ptr);
	//deleted the native object
	private native void deleteElement(long ptr);
	
	/**
	 * Returns pointer to the native CryptoPP Integer object.
	 * @return the pointer to the native object
	 */
	public long getPointerToElement() {
		return pointerToInteger;
	}
	
	/**
	 * Returns the value of the native Integer object as BigInteger.
	 * @return the BigInteger value of the native element
	 */
	public BigInteger getElement() {
		/*
		 * The function getElement returns the Integer value as byte array.
		 * BigInteger has a constructor that accepts this byte array and returns a BigInteger object with the same value as the Integer.
		 */
		return new BigInteger(getElement(pointerToInteger));
	}
	
	/**
	 * deletes the related trapdoor permutation object
	 */
	protected void finalize() throws Throwable {
		
		//deletes from the dll the dynamic allocation of the Integer.
		deleteElement(pointerToInteger);
		
		super.finalize();
	}
	
	//loads the dll
	 static {
	        System.loadLibrary("CryptoPPJavaInterface");
	 }
}
