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
package edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.cramerShoupEncryptedValue;

import java.io.IOException;
import java.io.ObjectOutputStream;

import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaCommonInput;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.CramerShoupPublicKey;
import edu.biu.scapi.midLayer.ciphertext.CramerShoupOnGroupElementCiphertext;
import edu.biu.scapi.primitives.dlog.GroupElement;

/**
 * Concrete implementation of SigmaProtocol input, used by the SigmaCramerShoupEncryptedValue verifier and simulator.<p>
 * 
 * In SigmaCramerShoupEncryptedValue protocol, the common input contains a GroupElement x, a CramerShoup public key
 * and the ciphertext of x using the CramerShoup encryption scheme.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaCramerShoupEncryptedValueCommonInput implements SigmaCommonInput{
	
	private static final long serialVersionUID = 6613096710529810429L;
	
	private GroupElement x;
	private CramerShoupPublicKey publicKey;
	private CramerShoupOnGroupElementCiphertext cipher;
	
	/**
	 * Sets the ciphertext, public key and the encrypted element.
	 * @param cipher ciphertext the output of the encryption scheme on the encrypted element.
	 * @param publicKey used to encrypt.
	 * @param x encrypted element.
	 */
	public SigmaCramerShoupEncryptedValueCommonInput(CramerShoupOnGroupElementCiphertext cipher, CramerShoupPublicKey publicKey, GroupElement x){
		this.cipher = cipher;
		this.publicKey = publicKey;
		this.x = x;
	}
	
	/**
	 * Returns the encrypted element.
	 * @return the encrypted element.
	 */
	public GroupElement getX() {
		return x;
	}

	/**
	 * Returns the public key used to encrypt.
	 * @return the public key used to encrypt.
	 */
	public CramerShoupPublicKey getPublicKey() {
		return publicKey;
	}

	/**
	 * Returns the ciphertext.
	 * @return the ciphertext.
	 */
	public CramerShoupOnGroupElementCiphertext getCipher() {
		return cipher;
	} 
	
	private void writeObject(ObjectOutputStream out) throws IOException {  
        
        out.writeObject(x.generateSendableData());  
        out.writeObject(publicKey.generateSendableData());
        out.writeObject(cipher.generateSendableData());
    }  
}

