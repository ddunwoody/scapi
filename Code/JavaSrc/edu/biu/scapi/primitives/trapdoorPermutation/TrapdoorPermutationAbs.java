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
package edu.biu.scapi.primitives.trapdoorPermutation;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;

import edu.biu.scapi.exceptions.ScapiRuntimeException;

/** 
 * This class implements some common functionality of trapdoor permutation.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 */
public abstract class TrapdoorPermutationAbs implements TrapdoorPermutation {
	
	protected PrivateKey privKey = null;        //private key
	protected PublicKey pubKey = null;          //public key
	protected BigInteger modulus = null;		//the modulus of the permutation. It must be such that modulus = p*q and p = q = 3 mod 4
	protected boolean isKeySet = false;		    // indicates if this object is initialized or not. Set to false until init is called

	
	public void setKey(PublicKey publicKey, PrivateKey privateKey) throws InvalidKeyException {
		//sets the class members with the keys
		pubKey = publicKey;
		privKey = privateKey;
		isKeySet = true; // mark this object as initialized
	}

	public void setKey(PublicKey publicKey) throws InvalidKeyException {
		//sets the class member with the public key
		pubKey = publicKey;
		isKeySet = true; // mark this object as initialized
	}
	

	public boolean isKeySet() {
		return isKeySet;
	}

	public PublicKey getPubKey(){
		if (!isKeySet()){
			throw new IllegalStateException("public key isn't set");
		}
		return pubKey;
	}
	
	public BigInteger getModulus(){
		if (!isKeySet()){
			throw new IllegalStateException("keys aren't set");
		}
		return modulus;
	}
	
	
	/** 
	 * Compute the hard core predicate of the given tpElement, by return the least significant bit of the element. 
	 *
	 * @param tpEl the element to compute the hard core predicate on
	 * @return byte the hard core predicate. In java, the smallest types are boolean and byte. 
	 * We chose to return a byte since many times we need to concatenate the result of various predicates 
	 * and it will be easier with a byte than with a boolean.
	 */
	public byte hardCorePredicate(TPElement tpEl) {
		if (!isKeySet()){
			throw new IllegalStateException("keys aren't set");
		}
		/*
		 *  We use this implementation both in RSA permutation and in Rabin permutation. 
		 * Thus, We implement it in TrapdoorPermutationAbs and let derived classes override it if needed. 
		 */
		//gets the element value as byte array
		BigInteger elementValue = tpEl.getElement();
		byte[] bytesValue = elementValue.toByteArray();
		
		//returns the least significant bit (byte, as we said above)
		return bytesValue[bytesValue.length - 1];
	}

	/** 
	 * Computes the hard core function of the given tpElement, by return the log (N) least significant bits of 
	 * the element. 
	 * @param tpEl the element to compute the hard core function on
	 * @return byte[] - log (N) least significant bits
	 */
	public byte[] hardCoreFunction(TPElement tpEl) {
		
		if (!isKeySet()){
			throw new IllegalStateException("keys aren't set");
		}
		/*
		 * We use this implementation both in RSA permutation and in Rabin permutation. 
		 * Thus, We implement it in TrapdoorPermutationAbs and let derived classes override it if needed. 
		 */
		//gets the element value as byte array
		BigInteger elementValue = tpEl.getElement();
		byte[] elementBytesValue = elementValue.toByteArray();
		
		//the number of bytes to get the log (N) least significant bits
		double logBits = (modulus.bitCount()/2);  //log N bits
		int logBytes = (int) Math.ceil(logBits/8); //log N bites in bytes
		
		//if the element length is less than log(N), the return byte[] should be all the element bytes
		int size = Math.min(logBytes, elementBytesValue.length);
		byte[] leastSignificantBytes = new byte[size];
		//copies the bytes to the output array
		System.arraycopy(elementBytesValue, elementBytesValue.length-size, leastSignificantBytes, 0, size);
		return leastSignificantBytes;
	
	}

}
