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
package edu.biu.scapi.midLayer.symmetricCrypto.encryption;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.SecretKey;

import edu.biu.scapi.primitives.prf.PseudorandomPermutation;

/**
 * This class performs the randomized Counter (CTR) Mode encryption and decryption, using OpenSSL library.
 * By definition, this encryption scheme is CPA-secure.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class OpenSSLCTREncRandomIV extends OpenSSLEncWithIVAbs implements CTREnc{

	//Native function that sets the encryption and decryption objects with the underlying prpName and key.
	private native void setKey(long enc, long dec, String prpName, byte[] secretKey); 
	
	/**
	 * Gets the name of the underlying prp that determines the type of encryption that will be performed.
	 * A default source of randomness is used.
	 * @param prp the underlying pseudorandom permutation to get the name of.
	 */
	public OpenSSLCTREncRandomIV(PseudorandomPermutation prp) {
		super(prp);
	}
	
	/**
	 * Gets the name of the underlying prp that determines the type of encryption that will be performed.
	 * The random passed to this constructor determines the source of randomness that will be used.
	 * @param prp the underlying pseudorandom permutation to get the name of.
	 * @param random a user provided source of randomness.
	 */
	public OpenSSLCTREncRandomIV(PseudorandomPermutation prp, SecureRandom random) {
		super(prp, random);
	}
	
	
	/**
	 * Sets the name of a Pseudorandom permutation and the name of a Random Number Generator Algorithm to use to generate the source of randomness.<p>
	 * @param prpName the name of a specific Pseudorandom permutation, for example "AES".
	 * @param randNumGenAlg  the name of the RNG algorithm, for example "SHA1PRNG".
	 * @throws NoSuchAlgorithmException  if the given randNumGenAlg is not a valid random number generator.
	 */
	public OpenSSLCTREncRandomIV(String prpName, String randNumGenAlg) throws NoSuchAlgorithmException {
		super(prpName, randNumGenAlg);	
	}
	
	/**
	 * Sets the name of a Pseudorandom permutation and the source of randomness.<p>
	 * The given prpName should be a name of prp algorithm such that OpenSSL provides a CTR encryption with.
	 * The only valid name is AES.
	 * @param prpName the name of a specific Pseudorandom permutation, for example "AES".
	 * @param random  a user provided source of randomness.
	 * @throw IllegalArgumentException in case the given prpName is not valid for this encryption scheme.
	 */
	public OpenSSLCTREncRandomIV(String prpName, SecureRandom random) {
		super(prpName, random);		
	}
	
	/**
	 * Checks the validity of the given prp name.
	 * In the CBC case, the valid prp name is AES.
	 */
	protected  boolean checkExistance(String prpName){
		//If the given name is "AES" return true; otherwise, return false.
		if (prpName.equals("AES")){
			return true;
		} else{
			return false;
		}
	}

	/**
	 * Supply the encryption scheme with a Secret Key.
	 */
	public void setKey(SecretKey secretKey) throws InvalidKeyException{
		super.setKey(secretKey);
		//Call the native function that sets the prp name and key.
		setKey(enc, dec, prpName, secretKey.getEncoded()); 
		
	}

	/**
	 * @return the algorithm name - CTR and the underlying prp name.
	 */
	@Override
	public String getAlgorithmName() {
		return "CTR Encryption with" + prpName;
		
	}

	static {
		//loads the OpenSSL dll.
		 System.loadLibrary("OpenSSLJavaInterface");
	}

}
