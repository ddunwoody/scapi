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

import java.io.IOException;
import java.util.Hashtable;
import java.util.Map;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.BasicReceiverCommitPhaseOutput;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.ReceiverCommitPhaseOutput;
import edu.biu.scapi.midLayer.asymmetricCrypto.encryption.ElGamalEnc;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.securityLevel.DDH;

/**
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */

public abstract class ElGamalCTRCore{
	protected Map<Integer , CTCElGamalCommitmentMessage> commitmentMap;
	protected DlogGroup dlog;
	protected Channel channel;
	protected ElGamalEnc elGamal;

	
	public ElGamalCTRCore(Channel channel, DlogGroup dlog, ElGamalEnc elGamal) throws IllegalArgumentException, SecurityLevelException, InvalidDlogGroupException{
		doConstruct(channel, dlog, elGamal);
	}



	private void doConstruct(Channel channel, DlogGroup dlog, ElGamalEnc elGamal) throws SecurityLevelException, InvalidDlogGroupException{
		//The underlying dlog group must be DDH secure.
		if (!(dlog instanceof DDH)){
			throw new SecurityLevelException("DlogGroup should have DDH security level");
		}
		if(!dlog.validateGroup())
			throw new InvalidDlogGroupException();

		this.channel = channel;
		this.dlog = dlog;
		commitmentMap = new Hashtable<Integer, CTCElGamalCommitmentMessage>();
		//elGamal = new ScElGamalOnGroupElement(dlog);
		this.elGamal = elGamal;
	}



	/* (non-Javadoc)`
	 * @see edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CTReceiver#preProcess()
	 */
	public void preProcess() throws IOException {
		//No pre-process in ElGamal Commitment
	}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CTReceiver#receiveCommitment()
	 */
	public ReceiverCommitPhaseOutput receiveCommitment() throws ClassNotFoundException, IOException {
		CTCElGamalCommitmentMessage msg = null;
		try{
			msg = (CTCElGamalCommitmentMessage) channel.receive();
		} catch (ClassNotFoundException e) {
			throw new ClassNotFoundException("Failed to receive commitment. The error is: " + e.getMessage());
		} catch (IOException e) {
			throw new IOException("Failed to receive commitment. The error is: " + e.getMessage());
		}

		commitmentMap.put(Integer.valueOf(msg.getId()), msg);
		return new BasicReceiverCommitPhaseOutput(msg.getId());
	}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CTReceiver#receiveDecommitment(int)
	 */
	public CommitValue receiveDecommitment(int id) throws ClassNotFoundException, IOException, IllegalArgumentException {
		CTCElGamalDecommitmentMessage msg = null;
		try {
			msg = (CTCElGamalDecommitmentMessage) channel.receive();

		} catch (ClassNotFoundException e) {
			throw new ClassNotFoundException("Failed to receive decommitment. The error is: " + e.getMessage());
		} catch (IOException e) {
			throw new IOException("Failed to receive decommitment. The error is: " + e.getMessage());
		}
	
		return processDecommitment(id, msg);
	}

	protected abstract CommitValue processDecommitment(int id, CTCElGamalDecommitmentMessage msg);
}
