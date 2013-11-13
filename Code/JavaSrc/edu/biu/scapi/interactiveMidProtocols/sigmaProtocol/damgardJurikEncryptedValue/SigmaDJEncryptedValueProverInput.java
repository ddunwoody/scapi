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
package edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.damgardJurikEncryptedValue;

import java.math.BigInteger;

import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProverInput;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.DamgardJurikPrivateKey;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.DamgardJurikPublicKey;
import edu.biu.scapi.midLayer.ciphertext.BigIntegerCiphertext;
import edu.biu.scapi.midLayer.plaintext.BigIntegerPlainText;

/**
 * Concrete implementation of SigmaProtocol input, used by the SigmaDamgardJurikEncryptedValueProver.<p>
 * In SigmaProtocolDamgardJurikEncryptedValue, the prover gets DamgardJurikPublicKey, BigIntegerCiphertext, BigIntegerPlaintext and the random BigInteger used to encrypt.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaDJEncryptedValueProverInput implements SigmaProverInput{
	
	private SigmaDJEncryptedValueCommonInput params;
	private BigInteger r;
	
	/**
	 * Sets the given public key, ciphertext, plaintext and random value used to encrypt.
	 * @param publicKey used to encrypt.
	 * @param cipher encryption on the given plaintext.
	 * @param plaintext that has been encrypted.
	 * @param r random value used to encrypt.
	 */
	public SigmaDJEncryptedValueProverInput(DamgardJurikPublicKey publicKey, BigIntegerCiphertext cipher, BigIntegerPlainText plaintext, BigInteger r){
		params = new SigmaDJEncryptedValueCommonInput(publicKey, cipher, plaintext);
		this.r = r;
	}
	
	/**
	 * This protocol assumes that the prover knows the randomness used to encrypt. <p>
	 * If the prover knows the secret key, then it can compute (once) the value m=n^(-1) mod phi(n)=n^(-1) mod (p-1)(q-1).<p>
	 * Then, it can recover the randomness r from c by computing c^m mod n (this equals r^(n/n) mod n = r). <p>
	 * Once given r, the prover can proceed with the protocol.<p>
	 * @param publicKey used to encrypt.
	 * @param cipher encryption on the given plaintext.
	 * @param plaintext that has been encrypted.
	 * @param privateKey used for decrypt.
	 */
	public SigmaDJEncryptedValueProverInput(DamgardJurikPublicKey publicKey, BigIntegerCiphertext cipher, BigIntegerPlainText plaintext, DamgardJurikPrivateKey privateKey){
		params = new SigmaDJEncryptedValueCommonInput(publicKey, cipher, plaintext);
		//Calculate r from the given private key.
		BigInteger p = privateKey.getP();
		BigInteger q = privateKey.getQ();
		BigInteger pMinusOne = p.subtract(BigInteger.ONE);
		BigInteger qMinusOne = q.subtract(BigInteger.ONE);
		BigInteger n = p.multiply(q);
		//(p-1)*(q-1)
		BigInteger phiN = pMinusOne.multiply(qMinusOne);
		//m = n^(-1) mod (p-1)(q-1).
		BigInteger m = n.modInverse(phiN);
		//r = c^m mod n
		r = cipher.getCipher().modPow(m, n);
	}
	
	/**
	 * Returns the random value used to encrypt.
	 * @return random value used to encrypt.
	 */
	public BigInteger getR(){
		return r;
	}

	public SigmaDJEncryptedValueCommonInput getCommonParams() {
		return params;
	} 

}
