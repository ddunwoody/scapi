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
package edu.biu.scapi.interactiveMidProtocols.commitmentScheme.statisticalHash;

import java.io.IOException;

import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.CommitValueException;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCCommitmentMsg;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCDecommitmentMessage;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtReceiver;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtRCommitPhaseOutput;

/**
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class StatisticalHashCTReceiver implements CmtReceiver {

	/* (non-Javadoc)
	 * @see edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CTReceiver#receiveCommitment()
	 */
	@Override
	public CmtRCommitPhaseOutput receiveCommitment()throws ClassNotFoundException, IOException {
		return null;
	}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CTReceiver#receiveDecommitment(long)
	 */
	@Override
	public CmtCommitValue receiveDecommitment(long id)	throws ClassNotFoundException, IOException, CommitValueException, CheatAttemptException {
		return null;
	}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CTReceiver#getPreProcessedValues()
	 */
	@Override
	public Object[] getPreProcessedValues() {
		// TODO Auto-generated method stub
		return null;
	}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CTReceiver#getCommitmentPhaseValues(long)
	 */
	@Override
	public Object getCommitmentPhaseValues(long id) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] generateBytesFromCommitValue(CmtCommitValue value) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public CmtCommitValue verifyDecommitment(CmtCCommitmentMsg commitmentMsg,
			CmtCDecommitmentMessage decommitmentMsg) {
		// TODO Auto-generated method stub
		return null;
	}

}
