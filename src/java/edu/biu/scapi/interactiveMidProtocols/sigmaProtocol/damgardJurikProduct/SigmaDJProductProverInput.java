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
package edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.damgardJurikProduct;

import java.math.BigInteger;

import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProverInput;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.DamgardJurikPrivateKey;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.DamgardJurikPublicKey;
import edu.biu.scapi.midLayer.ciphertext.BigIntegerCiphertext;
import edu.biu.scapi.midLayer.plaintext.BigIntegerPlainText;

/**
 * Concrete implementation of SigmaProtocol input, used by the SigmaDamgardJurikProductProver.<p>
 * In SigmaProtocolDamgardJurikProduct, the prover gets DamgardJurikPublicKey, three BigIntegerCiphertexts and three random BigIntegers used to encrypt.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaDJProductProverInput implements SigmaProverInput{
	
	private SigmaDJProductCommonInput params;
	private BigInteger r1;
	private BigInteger r2;
	private BigInteger r3;
	private BigIntegerPlainText x1;
	private BigIntegerPlainText x2;
	
	/**
	 * Sets the given public key, three ciphertexts, three random values, and two plaintexts.
	 * @param publicKey used to encrypt.
	 * @param c1 first ciphertext
	 * @param c2 second ciphertext
	 * @param c3 third ciphertext
	 * @param r1 first random number used to encrypt x1
	 * @param r2 first random number used to encrypt x2
	 * @param r3 first random number used to encrypt x3
	 * @param x1 first plaintext
	 * @param x2 second plaintext
	 */
	public SigmaDJProductProverInput(DamgardJurikPublicKey publicKey, 
							BigIntegerCiphertext c1, BigIntegerCiphertext c2, BigIntegerCiphertext c3, 
							BigInteger r1, BigInteger r2, BigInteger r3, BigIntegerPlainText x1, BigIntegerPlainText x2){
		params = new SigmaDJProductCommonInput(publicKey, c1, c2, c3);
		this.r1 = r1;
		this.r2 = r2;
		this.r3 = r3;
		this.x1 = x1;
		this.x2 = x2;	
	}
	
	/**
	 * This protocol assumes that the prover knows the randomness used to encrypt. 
	 * If the prover knows the secret key, then it can compute (once) the value m=n^(-1) mod phi(n)=n^(-1) mod (p-1)(q-1). 
	 * Then, it can recover the randomness ri from ci by computing ci^m mod n (this equals ri^(n/n) mod n = ri). 
	 * Once given r, the prover can proceed with the protocol.
	 * @param c1 first ciphertext
	 * @param c2 second ciphertext
	 * @param c3 third ciphertext
	 * @param privateKey used to recover r1, r2, r3
	 * @param x1 first plaintext
	 * @param x2 second plaintext
	 * 
	 */
	public SigmaDJProductProverInput(DamgardJurikPublicKey publicKey, 
							BigIntegerCiphertext c1, BigIntegerCiphertext c2, BigIntegerCiphertext c3, 
							DamgardJurikPrivateKey privateKey, BigIntegerPlainText x1, BigIntegerPlainText x2){
		params = new SigmaDJProductCommonInput(publicKey, c1, c2, c3);
		this.x1 = x1;
		this.x2 = x2;
		
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
		//ri = ci^m mod n
		r1 = c1.getCipher().modPow(m, n);
		r2 = c2.getCipher().modPow(m, n);
		r3 = c3.getCipher().modPow(m, n);
	}
	
	/**
	 * Returns the random number used to encrypt r1.
	 * @return the random number used to encrypt r1.
	 */
	public BigInteger getR1(){
		return r1;
	}
	
	/**
	 * Returns the random number used to encrypt r2.
	 * @return the random number used to encrypt r2.
	 */
	public BigInteger getR2(){
		return r2;
	}
	
	/**
	 * Returns the random number used to encrypt r3.
	 * @return the random number used to encrypt r3.
	 */
	public BigInteger getR3(){
		return r3;
	}
	
	/**
	 * Returns the first plaintext. 
	 * @return the first plaintext. 
	 */
	public BigIntegerPlainText getX1(){
		return x1;
	}
	
	/**
	 * Returns the second plaintext. 
	 * @return the second plaintext. 
	 */
	public BigIntegerPlainText getX2(){
		return x2;
	}

	@Override
	public SigmaDJProductCommonInput getCommonParams() {
		
		return params;
	} 
}
