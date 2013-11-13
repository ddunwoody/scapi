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

import java.io.IOException;
import java.io.ObjectOutputStream;

import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaCommonInput;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.DamgardJurikPublicKey;
import edu.biu.scapi.midLayer.ciphertext.BigIntegerCiphertext;

/**
 * Concrete implementation of SigmaProtocol input, used by the SigmaDamgardJurikProduct verifier and simulator.<p>
 * In SigmaProtocolDamgardJurikProduct, the common input contains DamgardJurikPublicKey and three BigIntegerCiphertexts.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaDJProductCommonInput implements SigmaCommonInput{
	
	private static final long serialVersionUID = 2474346914281126954L;
	
	private DamgardJurikPublicKey publicKey;
	private BigIntegerCiphertext cipher1;
	private BigIntegerCiphertext cipher2;
	private BigIntegerCiphertext cipher3;
	
	/**
	 * Sets the given public key and three ciphertexts.
	 * @param publicKey used to encrypt.
	 * @param c1 first ciphertext
	 * @param c2 second ciphertext
	 * @param c3 third ciphertext
	 */
	public SigmaDJProductCommonInput(DamgardJurikPublicKey publicKey, BigIntegerCiphertext c1, BigIntegerCiphertext c2, BigIntegerCiphertext c3){
		this.publicKey = publicKey;
		cipher1 = c1;
		cipher2 = c2;
		cipher3 = c3;
	}
	
	/**
	 * Returns the public key used to encrypt.
	 * @return the public key used to encrypt.
	 */
	public DamgardJurikPublicKey getPublicKey(){
		return publicKey;
	}
	
	/**
	 * Returns the first ciphertext.
	 * @return the first ciphertext.
	 */
	public BigIntegerCiphertext getC1(){
		return cipher1;
	}
	
	/**
	 * Returns the second ciphertext.
	 * @return the second ciphertext.
	 */
	public BigIntegerCiphertext getC2(){
		return cipher2;
	}
	
	/**
	 * Returns the third ciphertext.
	 * @return the third ciphertext.
	 */
	public BigIntegerCiphertext getC3(){
		return cipher3;
	}
	
	private void writeObject(ObjectOutputStream out) throws IOException {  
        
        out.writeObject(publicKey.generateSendableData());  
        out.writeObject(cipher1);
        out.writeObject(cipher2);
        out.writeObject(cipher3);
    } 
}
