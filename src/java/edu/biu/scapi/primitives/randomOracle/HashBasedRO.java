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
package edu.biu.scapi.primitives.randomOracle;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.primitives.hash.cryptopp.CryptoPpSHA1;
import edu.biu.scapi.tools.Factories.CryptographicHashFactory;

/**
 * Concrete class of random oracle based on CryptographicHash.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class HashBasedRO implements RandomOracle{
	
	private CryptographicHash hash; //The underlying object used to compute the random oracle function.
	
	/**
	 * default constructor that sets default values to the underlying cryptographic hash.
	 */
	public HashBasedRO(){
		this(new CryptoPpSHA1());
	}

	
	/**
	 * Constructor that gets a cryptographic hash object and sets it to the class member.
	 * @param hash
	 */
	public HashBasedRO(CryptographicHash hash){
		this.hash = hash;
	}
	
	/**
	 * Constructor that gets a cryptographic hash name, creates the corresponding object and sets it to the class member.
	 * @param hash
	 * @throws FactoriesException 
	 */
	public HashBasedRO(String hashName) throws FactoriesException{
		this(CryptographicHashFactory.getInstance().getObject(hashName));
	}

	/**
	 * Computes the random oracle function on the given input.
	 * @param input input to compute the random oracle function on.
	 * @param inOffset offset within the input to take the bytes from.
	 * @param inLen length of the input.
	 * @param outLen required output length in BYTES.
	 * @return a string in the required length.
	 */
	public byte[] compute(byte[] input, int inOffset, int inLen, int outLen){
		if (outLen>hash.getHashedMsgSize()){
			throw new IllegalArgumentException("The given output length is greater then the output length of the hash function");
		}
		//Call the hash function with the input.
		hash.update(input, inOffset, inLen);
		
		//Create output array in the required size.
		byte[] out = new byte[hash.getHashedMsgSize()];
		
		//Compute the hash function.
		hash.hashFinal(out, 0);
		
		byte[] output = new byte[outLen];
		if (out.length > outLen){
			System.arraycopy(out, 0, output, 0, outLen);
		} else{
			output = out;
		}
		return output;
	}


	@Override
	public String getAlgorithmName() {
		
		return "HashBasedRO";
	}

}
