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
package edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.elGamalEncryptedValue;

import java.math.BigInteger;

import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProverInput;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ElGamalPublicKey;
import edu.biu.scapi.midLayer.ciphertext.ElGamalOnGroupElementCiphertext;
import edu.biu.scapi.primitives.dlog.GroupElement;

/**
 * Concrete implementation of SigmaProtocol input, used by the SigmaElGamalEncryptedValueProver.<p>
 * 
 * There are two versions of SigmaElGamalEncryptedValue protocol, depending upon if the prover knows 
 * the secret key or it knows the randomness used to generate the ciphertext.<p>
 * This input represent the case that the prover knows the randomness. <p>
 * Thus, the prover gets a GroupElement x, an ElGamal public key,
 * the ciphertext of x using the ElGamal encryption scheme and the randomness used to encrypt.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaElGamalEncryptedValueRandomnessProverInput implements SigmaProverInput{

	private SigmaElGamalEncryptedValueCommonInput params;
	private BigInteger r;
	
	/**
	 * Sets the given ciphertext, public key, encrypted value and random value used to encrypt.<p>
	 * @param isRandomness represents if the encryption was done by private key knowledge or by a randomness knowledge.
	 * @param cipher ciphertext outputed by the encryption scheme on the given x
	 * @param publicKey used to encrypt.
	 * @param x encrypted value
	 * @param r random value used to encrypt.
	 */
	public SigmaElGamalEncryptedValueRandomnessProverInput(ElGamalOnGroupElementCiphertext cipher, ElGamalPublicKey pubKey, GroupElement x, BigInteger r){
		params = new SigmaElGamalEncryptedValueCommonInput(true, cipher, pubKey, x);
		this.r = r;
	}
	
	/**
	 * Returns the random value used to encrypt.
	 * @return the random value used to encrypt.
	 */
	public BigInteger getR(){
		return r;
	}
	
	@Override
	public SigmaElGamalEncryptedValueCommonInput getCommonParams() {
		return params;
	}
}
