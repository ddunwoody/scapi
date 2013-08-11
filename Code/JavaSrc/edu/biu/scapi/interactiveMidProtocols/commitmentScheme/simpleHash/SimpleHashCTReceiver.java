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

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Map;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.BasicReceiverCommitPhaseOutput;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.BigIntegerCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.ByteArrayCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CTReceiver;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.ReceiverCommitPhaseOutput;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.elGamal.CTCElGamalCommitmentMessage;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.elGamal.CTCElGamalDecommitmentMessage;
import edu.biu.scapi.midLayer.asymmetricCrypto.encryption.ElGamalEnc;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.securityLevel.SecureCommit;

/**
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class SimpleHashCTReceiver implements CTReceiver, SecureCommit {
	protected Map<Integer , CTCSimpleHashCommitmentMessage> commitmentMap;
	protected DlogGroup dlog;
	protected Channel channel;	
	private CryptographicHash hash;
	private int t;
	private int n;

	public SimpleHashCTReceiver(Channel channel, CryptographicHash hash, int t, int n) {
		this.channel = channel;
		this.hash = hash;
		this.t = t;
		this.n = n;
	}

	@Override
	public void preProcess() throws IOException {
		//No pre-process in SimpleHash Commitment
	}

	@Override
	public ReceiverCommitPhaseOutput receiveCommitment() throws ClassNotFoundException, IOException {
		CTCSimpleHashCommitmentMessage msg = null;
		try{
			msg = (CTCSimpleHashCommitmentMessage) channel.receive();
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
	@Override
	public CommitValue receiveDecommitment(int id) throws ClassNotFoundException, IOException{
		CTCSimpleHashDecommitmentMessage msg = null;
		try {
			msg = (CTCSimpleHashDecommitmentMessage) channel.receive();

		} catch (ClassNotFoundException e) {
			throw new ClassNotFoundException("Failed to receive decommitment. The error is: " + e.getMessage());
		} catch (IOException e) {
			throw new IOException("Failed to receive decommitment. The error is: " + e.getMessage());
		}

		return processDecommitment(id, msg);
	}

	private CommitValue processDecommitment(int id, CTCSimpleHashDecommitmentMessage msg){
		//Calculate c' = H(r|x)
		//If c' == c and x is a binary string of length t then ACCEPT
		//Else, REJECT
		
	
		byte[] x = msg.getX();
		//Reject already here if the length of x is not t
		if(x.length != t){
			System.out.println("Rejecting because length of x is: " + x.length + " is different from t: " + t);
			return null;
		}
		byte[] r = msg.getR();
		//create an array that will hold the concatenation of r with x
		byte[] cTag = new byte[n+t];
		System.arraycopy(r,0, cTag, 0, r.length);
		System.arraycopy(x, 0, cTag, r.length, x.length);
		byte[] hashValArrayTag = new byte[hash.getHashedMsgSize()];
		hash.update(cTag, 0, cTag.length);
		hash.hashFinal(hashValArrayTag, 0);
		//Fetch received commitment according to ID
		byte[] receivedCommitment = commitmentMap.get(Integer.valueOf(id)).getC();
		if (receivedCommitment.equals(hashValArrayTag))
			return new ByteArrayCommitValue(x);
		//In the pseudocode it says to return X and ACCEPT if valid commitment else, REJECT.
		//For now we return null as a mode of reject. If the returned value of this function is not null then it means ACCEPT
		return null;

	}
}
