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
package edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.elGamalCommittedValue;

import java.io.IOException;
import java.io.ObjectOutputStream;

import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaCommonInput;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ElGamalPublicKey;
import edu.biu.scapi.midLayer.ciphertext.ElGamalCiphertextSendableData;
import edu.biu.scapi.primitives.dlog.GroupElement;

/**
 * Concrete implementation of SigmaProtocol input, used by the SigmaElGamalCommittedValue verifier and simulator.<p>
 * In SigmaElGamalCommittedValue protocol, the common input contains an ElGamal commitment message
 * and the value committed x.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaElGamalCommittedValueCommonInput implements SigmaCommonInput{
	
	private static final long serialVersionUID = 7108469354272702947L;
	private ElGamalPublicKey publicKey;
	private ElGamalCiphertextSendableData commitment;
	private GroupElement x;
	
	/**
	 * Sets the public key, the commitment value and the committed value.
	 * @param publicKey used to commit the committed value.
	 * @param commitment the actual commitment value.
	 * @param x committed value.
	 */
	public SigmaElGamalCommittedValueCommonInput(ElGamalPublicKey publicKey, ElGamalCiphertextSendableData commitment, GroupElement x){
		this.publicKey = publicKey;
		this.commitment = commitment;
		this.x = x;
	}
	
	/**
	 * Returns the actual commitment value.
	 * @return the actual commitment value.
	 */
	public ElGamalCiphertextSendableData getCommitment(){
		return commitment;
	}
	
	/**
	 * Returns the committed value.
	 * @return the committed value.
	 */
	public GroupElement getX(){
		return x;
	}
	
	/**
	 * Returns the public key used to commit.
	 * @return the public key used to commit.
	 */
	public ElGamalPublicKey getPublicKey(){
		return publicKey;
	}
	
	private void writeObject(ObjectOutputStream out) throws IOException {  
		out.writeObject(publicKey.generateSendableData());  
		out.writeObject(commitment);  
		out.writeObject(x.generateSendableData());  
    }  
}
