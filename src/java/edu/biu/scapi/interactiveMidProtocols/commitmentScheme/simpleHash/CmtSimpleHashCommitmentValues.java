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
package edu.biu.scapi.interactiveMidProtocols.commitmentScheme.simpleHash;

import edu.biu.scapi.interactiveMidProtocols.ByteArrayRandomValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitmentPhaseValues;

/**
 * This class holds the values used by the SimpleHash Committer during the commitment phase
 * for a specific value that the committer commits about.
 * This value is kept attached to a random value used to calculate the commitment, 
 * which is also kept together in this structure.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class CmtSimpleHashCommitmentValues implements CmtCommitmentPhaseValues {
	//The random value used in the computation of the commitment for the specific commitval.
	ByteArrayRandomValue r;
	//The value that the committer commits about. This value is not sent to the receiver in the commitment phase, it is sent in the decommitment phase.
	CmtCommitValue commitval;
	//The value that the committer sends to the receiver in order to commit commitval in the commitment phase.
	byte[] computedCommitment;
	
	/**
	 * Constructor that sets the given random value, committed value and the commitment object.
	 * This constructor is package private. It should only be used by the classes in the package.
	 * @param r random value used for commit.
	 * @param commitVal the committed value
	 * @param computedCommitment the commitment 
	 */
	CmtSimpleHashCommitmentValues(ByteArrayRandomValue r, CmtCommitValue commitval, byte[] computedCommitment) {
		this.r = r;
		this.commitval = commitval;
		this.computedCommitment = computedCommitment;
	}

	/**
	 * @see edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitmentPhaseValues#getR()
	 */
	@Override
	public ByteArrayRandomValue getR() {
		
		return r;
	}

	/**
	 * @see edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitmentPhaseValues#getX()
	 */
	@Override
	public CmtCommitValue getX() {
		return commitval;
	}

	/**
	 * @see edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitmentPhaseValues#getComputedCommitment()
	 */
	@Override
	public byte[] getComputedCommitment() {
		return computedCommitment;
	}

}
