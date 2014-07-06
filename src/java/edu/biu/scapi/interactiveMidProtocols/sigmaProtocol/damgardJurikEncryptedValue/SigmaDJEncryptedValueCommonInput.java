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

import java.io.IOException;
import java.io.ObjectOutputStream;

import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaCommonInput;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.DamgardJurikPublicKey;
import edu.biu.scapi.midLayer.ciphertext.BigIntegerCiphertext;
import edu.biu.scapi.midLayer.plaintext.BigIntegerPlainText;

/**
 * Concrete implementation of SigmaProtocol input, used by the SigmaDamgardJurikEncryptedValue verifier and simulator.<p>
 * In SigmaProtocolDamgardJurikEncryptedValue, the common input contains DamgardJurikPublicKey, BigIntegerCiphertext and BigIntegerPlaintext.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaDJEncryptedValueCommonInput implements SigmaCommonInput{
	
	private static final long serialVersionUID = -5915961233248748044L;
	
	private DamgardJurikPublicKey publicKey;
	private BigIntegerCiphertext cipher;
	private BigIntegerPlainText plaintext;
	
	/**
	 * Sets the given public key, ciphertext and plaintext.
	 * @param publicKey used to encrypt.
	 * @param cipher encryption on the given plaintext.
	 * @param plaintext that has been encrypted.
	 */
	public SigmaDJEncryptedValueCommonInput(DamgardJurikPublicKey publicKey, BigIntegerCiphertext cipher, BigIntegerPlainText plaintext){
		this.publicKey = publicKey;
		this.cipher = cipher;
		this.plaintext = plaintext;
	}
	
	/**
	 * Returns the public key used to encrypt.
	 * @return public key used to encrypt.
	 */
	public DamgardJurikPublicKey getPublicKey(){
		return publicKey;
	}
	
	/**
	 * Returns the ciphertext which is an encryption on the plaintext.
	 * @return  ciphertext which is an encryption on the plaintext.
	 */
	public BigIntegerCiphertext getCiphertext(){
		return cipher;
	}
	
	/**
	 * Returns the plaintext that has been encrypted.
	 * @return the plaintext that has been encrypted.
	 */
	public BigIntegerPlainText getPlaintext(){
		return plaintext;
	}
	
	private void writeObject(ObjectOutputStream out) throws IOException {  
        
        out.writeObject(publicKey.generateSendableData());  
        out.writeObject(cipher);
        out.writeObject(plaintext);
    } 
}
