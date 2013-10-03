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

import javax.crypto.SecretKey;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.primitives.kdf.HKDF;
import edu.biu.scapi.primitives.kdf.KeyDerivationFunction;
import edu.biu.scapi.primitives.prf.bc.BcHMAC;
import edu.biu.scapi.tools.Factories.KdfFactory;

/**
 * Concrete class of random oracle based on HKDF.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class HKDFBasedRO implements RandomOracle{
	
	private HKDF hkdf; //The underlying object used to compute the random oracle function.
	
	/**
	 * default constructor that sets default values to the underlying HKDF.
	 */
	public HKDFBasedRO(){
		this(new HKDF(new BcHMAC()));
	}

	
	/**
	 * Constructor that gets a HKDF object and sets it to the class member.
	 * @param hkdf
	 */
	public HKDFBasedRO(HKDF hkdf){
		this.hkdf = hkdf;
	}
	
	/**
	 * Constructor that gets a HKDF name, creates the corresponding object and sets it to the class member.
	 * @param hkdf
	 * @throws FactoriesException 
	 */
	public HKDFBasedRO(String hkdfName) throws FactoriesException{
		KeyDerivationFunction hkdf = KdfFactory.getInstance().getObject(hkdfName);
		if (!(hkdf instanceof HKDF)){
			throw new IllegalArgumentException("The given name is not an HKDF name");
		}
		this.hkdf = (HKDF) hkdf;
	}

	/**
	 * Computes the random oracle function on the given input.
	 * @param input input to compute the random oracle function on.
	 * @param inOffset offset within the input to take the bytes from.
	 * @param inLen length of the input.
	 * @param outLen required output length IN BYTES.
	 * @return a string in the required length.
	 */
	public byte[] compute(byte[] input, int inOffset, int inLen, int outLen){
		//Call the HKDF function with input, output length and iv = "RandomOracle".
		SecretKey key = hkdf.deriveKey(input, inOffset, inLen, outLen, "RandomOracle".getBytes());
		return key.getEncoded();
	}
	
	@Override
	public String getAlgorithmName() {
		
		return "HKDFBasedRO";
	}
}
