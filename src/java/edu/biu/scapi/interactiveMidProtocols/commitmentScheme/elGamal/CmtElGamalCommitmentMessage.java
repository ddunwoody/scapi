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
package edu.biu.scapi.interactiveMidProtocols.commitmentScheme.elGamal;

import java.io.Serializable;

import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCCommitmentMsg;
import edu.biu.scapi.midLayer.ciphertext.ElGamalCiphertextSendableData;

/**
 * Concrete implementation of commitment message used by ElGamal commitment scheme.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class CmtElGamalCommitmentMessage implements CmtCCommitmentMsg, Serializable {

	private static final long serialVersionUID = 8646902245380445237L;
	// In ElGamal schemes the commitment object is a ElGamalCiphertext
	//In order to this class be a serializable, we get it as ElGamalCiphertextSendableData. 
	private ElGamalCiphertextSendableData cipherData;
	private long id; //The id of the commitment
	
	/**
	 * Constructor that sets the commitment and id.
	 * @param cipherData the actual commitment object. In ElGamal schemes the commitment object is a ElGamalCiphertextSendableData.
	 * @param id the commitment id.
	 */
	public CmtElGamalCommitmentMessage(ElGamalCiphertextSendableData cipherData, long id) {
		super();
		this.cipherData = cipherData;
		this.id = id;
	}
	
	/**
	 * Returns the commitment value. In this case the instance of the commitment is ElGamalCiphertextSendableData.
	 */
	public ElGamalCiphertextSendableData getCommitment() {
		return cipherData;
	}
	
	/**
	 * Returns the commitment id.
	 */
	public long getId(){
		return id;
	}
	
	
}
