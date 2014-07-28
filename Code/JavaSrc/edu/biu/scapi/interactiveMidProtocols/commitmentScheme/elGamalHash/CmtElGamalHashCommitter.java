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
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtByteArrayCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCCommitmentMsg;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCDecommitmentMessage;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitter;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtOnByteArray;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.elGamal.CmtElGamalDecommitmentMessage;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.elGamal.CmtElGamalCommitterCore;
import edu.biu.scapi.midLayer.asymmetricCrypto.encryption.ScElGamalOnByteArray;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.miracl.MiraclDlogECF2m;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.primitives.hash.openSSL.OpenSSLSHA256;
import edu.biu.scapi.primitives.kdf.HKDF;
import edu.biu.scapi.primitives.prf.bc.BcHMAC;
import edu.biu.scapi.securityLevel.SecureCommit;

/**
 * This class implements the committer side of the ElGamal hash commitment. <p>
 * 
 * The pseudo code of this protocol can be found in Protocol 3.5 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class CmtElGamalHashCommitter extends CmtElGamalCommitterCore implements CmtCommitter, SecureCommit, CmtOnByteArray {

	/*
	 * runs the following protocol:
	 * "Run COMMIT_ELGAMAL to commit to value H(x). 
	 * For decommitment, send x and the receiver verifies that the commitment was to H(x)".
	 */
	
	private CryptographicHash hash;
	private Map<Long, byte[]> hashCommitmentMap;

	/**
	 * This constructor receives as argument the channel and chosses default values of 
	 * Dlog Group and Cryptographic Hash such that they keep the condition that the size in 
	 * bytes of the resulting hash is less than the size in bytes of the order of the DlogGroup.
	 * Otherwise, it throws IllegalArgumentException.
	 * An established channel has to be provided by the user of the class.
	 * @param channel
	 * @throws IOException In case there is a problem in the pre-process phase.
	 */
	public CmtElGamalHashCommitter(Channel channel) throws IOException {
		//This default hash suits the default DlogGroup.
		try {
			doConstruct(channel, new MiraclDlogECF2m("K-283"), new OpenSSLSHA256(), new SecureRandom());
		} catch (SecurityLevelException e) {
			// Should not occur since the default DlogGroup has the necessary security level.
		} catch (InvalidDlogGroupException e) {
			// Should not occur since the default DlogGroup is valid.
		}
	}
	

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
	public CmtElGamalHashCommitter(Channel channel, DlogGroup dlog, CryptographicHash hash, SecureRandom random) throws IllegalArgumentException, SecurityLevelException, InvalidDlogGroupException, IOException{
		doConstruct(channel, dlog, hash, random);
	}

	private void doConstruct(Channel channel, DlogGroup dlog, CryptographicHash hash, SecureRandom random) throws SecurityLevelException, InvalidDlogGroupException, IOException{
		//During the construction of this object, the Public Key with which we set the El Gamal object gets sent to the receiver.
		super.doConstruct(channel, dlog, new ScElGamalOnByteArray(dlog, new HKDF(new BcHMAC())), random);
		if (hash.getHashedMsgSize()> (dlog.getOrder().bitLength()/8)){
			throw new IllegalArgumentException("The size in bytes of the resulting hash is bigger than the size in bytes of the order of the DlogGroup.");
		}
		this.hash = hash;
		hashCommitmentMap = new Hashtable<Long, byte[]>();
	}
	
	/**
	 * Runs COMMIT_ElGamal to commit to value H(x).
	 * @return the created commitment.
	 */
	public CmtCCommitmentMsg generateCommitmentMsg(CmtCommitValue input, long id){
		
		byte[] hashValArray = getHashOfX(input, id);
		
		//After the input has been manipulated with the Hash call the super's commit function. Since the super has been initialized with ScElGamalOnByteArray
		//it will know how to take care of the byte array input.
		return super.generateCommitmentMsg(new CmtByteArrayCommitValue(hashValArray), id);
	}


	
	/**
	 * Runs COMMIT_ElGamal to commit to value H(x).
	 */
	public void commit(CmtCommitValue input, long id) throws IOException {
		byte[] hashValArray = getHashOfX(input, id);
		//After the input has been manipulated with the Hash call the super's commit function. Since the super has been initialized with ScElGamalOnByteArray
		//it will know how to take care of the byte array input.
		super.commit(new CmtByteArrayCommitValue(hashValArray), id);
	}
	
	/**
	 * Returns H(x).
	 * @param input should be an instance of CmtByteArrayCommitValue.
	 * @param id
	 * @return the result of the hash function of the given input.
	 */
	private byte[] getHashOfX(CmtCommitValue input, long id) {
		//Check that the input x is in the end a byte[]
		if (!(input instanceof CmtByteArrayCommitValue))
			throw new IllegalArgumentException("The input must be of type CmtByteArrayCommitValue");
		//Hash the input x with the hash function
		byte[] x  = ((CmtByteArrayCommitValue)input).getX();
		//Keep the original commit value x and its id in the commitmentMap, needed for later (during the decommit phase).
		hashCommitmentMap.put(Long.valueOf(id), x);
		
		//calculate H(x) = Hash(x)
		byte[] hashValArray = new byte[hash.getHashedMsgSize()];
		hash.update(x, 0, x.length);
		hash.hashFinal(hashValArray, 0);
		return hashValArray;
	}

	@Override
	public CmtCDecommitmentMessage generateDecommitmentMsg(long id){
		
		//Fetch the commitment according to the requested ID
		byte[] x = hashCommitmentMap.get(Long.valueOf(id));
		//Get the relevant random value used in the commitment phase
		BigIntegerRandomValue r = (commitmentMap.get(id)).getR();
				
		return new CmtElGamalDecommitmentMessage(x,r);
	}
	
	/**
	 * Sends x to the receiver.
	 */
	public void decommit(long id) throws IOException {
		
		CmtCDecommitmentMessage msg = generateDecommitmentMsg(id);
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
	public CmtCommitValue sampleRandomCommitValue(){
		byte[] val = new byte[32];
		random.nextBytes(val);
		return new CmtByteArrayCommitValue(val);
	}

	@Override
	public CmtCommitValue generateCommitValue(byte[] x)throws CommitValueException {
		return new CmtByteArrayCommitValue(x);
	}
	
	/**
	 * This function converts the given commit value to a byte array. 
	 * @param value
	 * @return the generated bytes.
	 */
	public byte[] generateBytesFromCommitValue(CmtCommitValue value){
		if (!(value instanceof CmtByteArrayCommitValue))
			throw new IllegalArgumentException("The given value must be of type CmtByteArrayCommitValue");
		return (byte[]) value.getX();
	}


}