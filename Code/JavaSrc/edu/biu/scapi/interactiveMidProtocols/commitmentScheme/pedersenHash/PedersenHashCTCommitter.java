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
import java.security.SecureRandom;
import java.util.Hashtable;
import java.util.Map;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.CommitValueException;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.BigIntegerCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.ByteArrayCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CTCommitter;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.OnBigIntegerCommitmentScheme;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.pedersen.CTCPedersenDecommitmentMessage;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.pedersen.PedersenCommitterCore;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.primitives.hash.bc.BcSHA224;
import edu.biu.scapi.securityLevel.PerfectlyHidingCT;

/**
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class PedersenHashCTCommitter extends PedersenCommitterCore implements CTCommitter, PerfectlyHidingCT, OnBigIntegerCommitmentScheme {
	//private PedersenCTCommitter pedCommitter;
	private CryptographicHash hash;
	private Map<Integer, byte[]> hashCommitmentMap;
	
	/**
	 * This constructor uses a default Dlog Group and default Cryptographic Hash. They keep the condition that 
	 * the size in bytes of the resulting hash is less than the size in bytes of the order of the DlogGroup.
	 * An established channel has to be provided by the user of the class.
	 * @param channel
	 * @throws IllegalArgumentException
	 * @throws SecurityLevelException
	 * @throws InvalidDlogGroupException
	 */
	public PedersenHashCTCommitter(Channel channel) throws IllegalArgumentException, SecurityLevelException, InvalidDlogGroupException{
		super(channel);
		this.hash = new BcSHA224(); 		//This default hash suits the default DlogGroup of the underlying Committer.
		//this.pedCommitter = new PedersenCTCommitter(channel);
		hashCommitmentMap = new Hashtable<Integer, byte[]>();
	}
	
	/**
	 * This constructor receives as arguments an instance of a Dlog Group and an instance of a Cryptographic Hash such that they keep the condition that 
	 * the size in bytes of the resulting hash is less than the size in bytes of the order of the DlogGroup. Otherwise, it throws IllegalArgumentException.
	 * An established channel has to be provided by the user of the class.
 
	 * @param channel an established channel obtained via the Communication Layer 
	 * @param dlog 
	 * @param hash
	 * @throws IllegalArgumentException if the size in bytes of the resulting hash is bigger than the size in bytes of the order of the DlogGroup
	 * @throws SecurityLevelException if the Dlog Group is not DDH
	 * @throws InvalidDlogGroupException if the parameters of the group do not conform the type the group is supposed to be
	 */
	public PedersenHashCTCommitter(Channel channel, DlogGroup dlog, CryptographicHash hash) throws IllegalArgumentException, SecurityLevelException, InvalidDlogGroupException{
		super(channel,dlog);
		if (hash.getHashedMsgSize()> (dlog.getOrder().bitLength()/8)){
			throw new IllegalArgumentException("The size in bytes of the resulting hash is bigger than the size in bytes of the order of the DlogGroup.");
		}
		this.hash = hash;
		//pedCommitter = new PedersenCTCommitter(channel, dlog);
		hashCommitmentMap = new Hashtable<Integer, byte[]>();
	}
	/**
	 * We do not provide a constructor that receives a DlogGroup and not a Hash or vice-versa, since they size of the resulting hash has to be less than the order of the group and we cannot 
	 * choose a relevant default for either the group of the hash. 
	 */
	
	/* (non-Javadoc)
	 * @see edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CTCommitter#preProcess()
	 */
	//@Override
	/*
	public void preProcess() throws ClassNotFoundException, IOException, CheatAttemptException {
		pedCommitter.preProcess();
	}
	*/
	/* (non-Javadoc)
	 * @see edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CTCommitter#commit(edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CommitValue, int)
	 */
	@Override
	public void commit(CommitValue input, int id) throws IOException, IllegalArgumentException {
		//Check that the input x is in the end a byte[]
		if (!(input instanceof ByteArrayCommitValue))
			throw new IllegalArgumentException("The input must be of type ByteArrayCommitValue");
		//Hash the input x with the hash function
		byte[] x  = ((ByteArrayCommitValue)input).getX();
		//Keep the original commit value x and its id in the commitmentMap, needed for later (during the decommit phase).
		hashCommitmentMap.put(Integer.valueOf(id), x);
		
		//calculate H(x) = Hash(x)
		byte[] hashValArray = new byte[hash.getHashedMsgSize()];
		hash.update(x, 0, x.length);
		hash.hashFinal(hashValArray, 0);
		//Use Pedersen commitment on the hashed value 
		//return pedCommitter.commit(new BigIntegerCommitValue(new BigInteger(hashValArray)), id);
		super.commit(new BigIntegerCommitValue(new BigInteger(hashValArray)), id);
	}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CTCommitter#decommit(int)
	 */
	@Override
	public void decommit(int id) throws IOException {

		//Fetch the commitment according to the requested ID
		byte[] x = hashCommitmentMap.get(Integer.valueOf(id));
		//Get the relevant random value used in the commitment phase
		//CTCPedersenDecommitmentMessage underMsg = (CTCPedersenDecommitmentMessage) computeDecommit(id);
		BigInteger r = (commitmentMap.get(id)).getR();
		//Is it OK to convert the byte[] x to BigInteger?
		CTCPedersenDecommitmentMessage msg = new CTCPedersenDecommitmentMessage(new BigInteger(x),r);
		try{
			channel.send(msg);
		}
		catch (IOException e) {
			throw new IOException("failed to send the message. The error is: " + e.getMessage());
		}
		//This is not according to the pseudo-code but for our programming needs. TODO Check if can be left.
		//return (CTCDecommitmentMessage) msg;
	}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CTCommitter#generateCommitValue(byte[])
	 */
	@Override
	public CommitValue generateCommitValue(byte[] x) throws CommitValueException {
		return new ByteArrayCommitValue(x);
	}

}