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
package edu.biu.scapi.interactiveMidProtocols.commitmentScheme.elGamalHash;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Hashtable;
import java.util.Map;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CommitValueException;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.BigIntegerRandomValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.ByteArrayCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CTCommitter;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.OnByteArrayCommitmentScheme;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.elGamal.CTCElGamalDecommitmentMessage;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.elGamal.ElGamalCTCCore;
import edu.biu.scapi.midLayer.asymmetricCrypto.encryption.ScElGamalOnByteArray;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.primitives.kdf.HKDF;
import edu.biu.scapi.primitives.prf.bc.BcHMAC;
import edu.biu.scapi.securityLevel.SecureCommit;

/**
 * This class implements the committer side of the ElGamal hash commitment. 
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class ElGamalHashCTCommitter extends ElGamalCTCCore implements CTCommitter, SecureCommit, OnByteArrayCommitmentScheme {

	/*
	 * runs the following protocol:
	 * "Run COMMIT_ELGAMAL to commit to value H(x). 
	 * For decommitment, send x and the receiver verifies that the commitment was to H(x)".
	 */
	
	private CryptographicHash hash;
	private Map<Long, byte[]> hashCommitmentMap;

	/*
	 *Too complicated to have a default constructor. Many things need to be suitable to each other. Cannot have some being default (and unknown to the caller) and some defined by the caller.
	public ElGamalHashCTCommitter(Channel channel) throws IllegalArgumentException, SecurityLevelException, InvalidDlogGroupException{
		super(channel, new );
		hash = new BcSHA224(); 		//This default hash suits the default DlogGroup of the underlying Committer.
		hashCommitmentMap = new Hashtable<Integer, byte[]>();
	}
	*/

	/**
	 * This constructor receives as arguments an instance of a Dlog Group and an instance 
	 * of a Cryptographic Hash such that they keep the condition that the size in bytes 
	 * of the resulting hash is less than the size in bytes of the order of the DlogGroup.
	 * Otherwise, it throws IllegalArgumentException.
	 * An established channel has to be provided by the user of the class.
	 * @param channel
	 * @param dlog
	 * @param hash
	 * @param random
	 * @throws IllegalArgumentException
	 * @throws SecurityLevelException
	 * @throws InvalidDlogGroupException
	 * @throws IOException
	 */
	public ElGamalHashCTCommitter(Channel channel, DlogGroup dlog, CryptographicHash hash, SecureRandom random) throws IllegalArgumentException, SecurityLevelException, InvalidDlogGroupException, IOException{
		//During the construction of this object, the Public Key with which we set the El Gamal object gets sent to the receiver.
		super(channel, dlog, new ScElGamalOnByteArray(dlog, new HKDF(new BcHMAC())), random);
		if (hash.getHashedMsgSize()> (dlog.getOrder().bitLength()/8)){
			throw new IllegalArgumentException("The size in bytes of the resulting hash is bigger than the size in bytes of the order of the DlogGroup.");
		}
		this.hash = hash;
		hashCommitmentMap = new Hashtable<Long, byte[]>();
	}


	/**
	 * Run COMMIT_ElGamal to commit to value H(x).
	 */
	public void commit(CommitValue input, long id) throws IOException {
		//Check that the input x is in the end a byte[]
		if (!(input instanceof ByteArrayCommitValue))
			throw new IllegalArgumentException("The input must be of type ByteArrayCommitValue");
		//Hash the input x with the hash function
		byte[] x  = ((ByteArrayCommitValue)input).getX();
		//Keep the original commit value x and its id in the commitmentMap, needed for later (during the decommit phase).
		hashCommitmentMap.put(Long.valueOf(id), x);

		//calculate H(x) = Hash(x)
		byte[] hashValArray = new byte[hash.getHashedMsgSize()];
		hash.update(x, 0, x.length);
		hash.hashFinal(hashValArray, 0);
		//After the input has been manipulated with the Hash call the super's commit function. Since the super has been initialized with ScElGamalOnByteArray
		//it will know how to take care of the byte array input.
		super.commit(new ByteArrayCommitValue(hashValArray), id);
	}


	/**
	 * Sends x to the receiver.
	 */
	public void decommit(long id) throws IOException {
		//Fetch the commitment according to the requested ID
		byte[] x = hashCommitmentMap.get(Long.valueOf(id));
		//Get the relevant random value used in the commitment phase
		BigIntegerRandomValue r = (commitmentMap.get(id)).getR();
		
		CTCElGamalDecommitmentMessage msg = new CTCElGamalDecommitmentMessage(x,r);
		try{
			channel.send(msg);
		}
		catch (IOException e) {
			throw new IOException("failed to send the message. The error is: " + e.getMessage());
		}
	}

	/**
	 * This function samples random commit value and returns it.
	 * @return the sampled commit value
	 */
	public CommitValue sampleRandomCommitValue(){
		byte[] val = new byte[32];
		random.nextBytes(val);
		return new ByteArrayCommitValue(val);
	}

	@Override
	public CommitValue generateCommitValue(byte[] x)throws CommitValueException {
		return new ByteArrayCommitValue(x);
	}
	
	/**
	 * This function converts the given commit value to a byte array. 
	 * @param value
	 * @return the generated bytes.
	 */
	public byte[] generateBytesFromCommitValue(CommitValue value){
		if (!(value instanceof ByteArrayCommitValue))
			throw new IllegalArgumentException("The given value must be of type ByteArrayCommitValue");
		return (byte[]) value.getX();
	}


}