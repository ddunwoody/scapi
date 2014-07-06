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
package edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.elGamalCmtKnowledge;

import java.io.IOException;
import java.io.ObjectOutputStream;

import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaCommonInput;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ElGamalPublicKey;

/**
 * Concrete implementation of SigmaProtocol input, used by the SigmaElGamalCTKnowldge verifier and simulator.<p>
 * In SigmaElGamalCTKnowldge protocol, the common input contains an ElGamal commitment message.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaElGamalCmtKnowledgeCommonInput implements SigmaCommonInput{

	private static final long serialVersionUID = 761506828568805999L;
	private ElGamalPublicKey publicKey;
	
	/**
	 * Sets the given ElGamal public key.
	 * @param publicKey used to commit.
	 */
	public SigmaElGamalCmtKnowledgeCommonInput(ElGamalPublicKey publicKey){
		this.publicKey = publicKey;
	}
	
	/**
	 * Returns the public key used for commit.
	 * @return the public key used for commit.
	 */
	public ElGamalPublicKey getPublicKey(){
		return publicKey;
	}
	
	private void writeObject(ObjectOutputStream out) throws IOException {  
		out.writeObject(publicKey.generateSendableData());    
    }  
}
