/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
Copyright (c) 2012 - SCAPI (http://crypto.biu.ac.il/scapi)
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

package edu.biu.scapi.interactiveMidProtocols.commitmentScheme.pedersenHash;

import java.io.IOException;
import java.math.BigInteger;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.ByteArrayCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CTReceiver;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.pedersen.CTCPedersenDecommitmentMessage;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.pedersen.PedersenReceiverCore;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.primitives.hash.bc.BcSHA224;
import edu.biu.scapi.securityLevel.PerfectlyHidingCT;
/**
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class PedersenHashCTReceiver extends PedersenReceiverCore implements CTReceiver, PerfectlyHidingCT {

	private CryptographicHash hash;
	
	
	public PedersenHashCTReceiver(Channel channel) throws IllegalArgumentException, SecurityLevelException, InvalidDlogGroupException{
		//pedersenCTReceiver = new PedersenCTReceiver(channel);
		super(channel);
		hash = new BcSHA224(); 		//This default hash suits the default DlogGroup of the underlying Committer.
	}
	
	
	public PedersenHashCTReceiver(Channel channel, DlogGroup dlog, CryptographicHash hash) throws IllegalArgumentException, SecurityLevelException, InvalidDlogGroupException{
		super(channel, dlog);
		if (hash.getHashedMsgSize()> (dlog.getOrder().bitLength()/8)){
			throw new IllegalArgumentException("The size in bytes of the resulting hash is bigger than the size in bytes of the order of the DlogGroup.");
		}
		this.hash = hash;
}


	/*
	@Override
	public void preProcess() throws IOException {
		pedersenCTReceiver.preProcess();
	}


	/* (non-Javadoc)
	 * @see edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CTReceiver#receiveCommitment()
	 */
/*	@Override
	public ReceiverCommitPhaseOutput receiveCommitment() throws ClassNotFoundException, IOException {
		return pedersenCTReceiver.receiveCommitment();
	}
	*/

	/* (non-Javadoc)
	 * @see edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CTReceiver#receiveDecommitment(int)
	 */
	@Override
	public CommitValue receiveDecommitment(int id) throws ClassNotFoundException, IOException {
		CTCPedersenDecommitmentMessage msg = null;
		try {
			msg = (CTCPedersenDecommitmentMessage) channel.receive();

		} catch (ClassNotFoundException e) {
			throw new ClassNotFoundException("Failed to receive decommitment. The error is: " + e.getMessage());
		} catch (IOException e) {
			throw new IOException("Failed to receive decommitment. The error is: " + e.getMessage());
		}

		//Hash the input x with the hash function
		byte[] x  = msg.getX().toByteArray();
		//calculate H(x) = Hash(x)
		byte[] hashValArray = new byte[hash.getHashedMsgSize()];
		hash.update(x, 0, x.length);
		hash.hashFinal(hashValArray, 0);
		
		CommitValue val = processDecommitment(id, new BigInteger(hashValArray), msg.getR());
		//If the inner Pedersen core algorithm returned null it means that it rejected the decommitment, so Pedersen Hash also rejects the answer and returns null
		if (val == null)
			return null;
		//The decommitment was accpeted by Pedersen core. Now, Pedersen Hash has to return the original value before the hashing.
		return new ByteArrayCommitValue(x);
	}

}