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

import java.io.IOException;
import java.io.ObjectOutputStream;

import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaCommonInput;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ElGamalPublicKey;
import edu.biu.scapi.midLayer.ciphertext.ElGamalOnGroupElementCiphertext;
import edu.biu.scapi.primitives.dlog.GroupElement;

/**
 * Concrete implementation of SigmaProtocol input, used by the SigmaElGamalEncryptedValue verifier and simulator.<p>
 * There are two versions of SigmaElGamalEncryptedValue protocol, depending upon if the prover knows 
 * the secret key or it knows the randomness used to generate the ciphertext.<p>
 * This common input contains an ElGamal public Key, the encrypted value x, the ciphertext and 
 * a boolean indicates is the prover knows the secret key or the random value.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaElGamalEncryptedValueCommonInput implements SigmaCommonInput{
	
	private static final long serialVersionUID = 3937743510337152514L;
	private boolean isRandomness;
	private GroupElement x;
	private ElGamalPublicKey publicKey;
	private ElGamalOnGroupElementCiphertext cipher;
	
	/**
	 * Sets the given ciphertext, public key and encrypted value.<p>
	 * There is also an argument represents if the encryption was done by private key knowledge or by a randomness knowledge.
	 * @param isRandomness represents if the encryption was done by private key knowledge or by a randomness knowledge.
	 * @param cipher ciphertext outputed by the encryption scheme on the given x
	 * @param publicKey used to encrypt.
	 * @param x encrypted value
	 */
	public SigmaElGamalEncryptedValueCommonInput(boolean isRandomness, ElGamalOnGroupElementCiphertext cipher, ElGamalPublicKey publicKey, GroupElement x){
		this.isRandomness = isRandomness;
		this.cipher = cipher;
		this.publicKey = publicKey;
		this.x = x;
	}
	
	/**
	 * Returns a boolean represents if the encryption was done by private key knowledge or by a randomness knowledge.
	 * @return a boolean represents if the encryption was done by private key knowledge or by a randomness knowledge.
	 */
	public boolean isRandomness() {
		return isRandomness;
	}
	
	/**
	 * Returns the encrypted value.
	 * @return the encrypted value.
	 */
	public GroupElement getX() {
		return x;
	}

	/**
	 * Returns the publicKey used to encrypt.
	 * @return the publicKey used to encrypt.
	 */
	public ElGamalPublicKey getPublicKey() {
		return publicKey;
	}

	/**
	 * Returns the ciphertext.
	 * @return the ciphertext.
	 */
	public ElGamalOnGroupElementCiphertext getCipher() {
		return cipher;
	}
	
	private void writeObject(ObjectOutputStream out) throws IOException {  
        
		out.writeObject(isRandomness);  
		out.writeObject(x.generateSendableData());  
		out.writeObject(publicKey.generateSendableData());
		out.writeObject(cipher.generateSendableData());
    }  

	
}
