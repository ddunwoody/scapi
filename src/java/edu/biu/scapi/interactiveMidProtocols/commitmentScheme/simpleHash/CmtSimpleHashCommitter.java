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
package edu.biu.scapi.interactiveMidProtocols.commitmentScheme.simpleHash;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Hashtable;
import java.util.Map;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CommitValueException;
import edu.biu.scapi.interactiveMidProtocols.ByteArrayRandomValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtByteArrayCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCCommitmentMsg;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCDecommitmentMessage;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitter;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitmentPhaseValues;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.primitives.hash.openSSL.OpenSSLSHA256;
import edu.biu.scapi.securityLevel.SecureCommit;

/**
 * This class implements the committer side of Simple Hash commitment.<p>
 * 
 * This is a commitment scheme based on hash functions. <p>
 * It can be viewed as a random-oracle scheme, but its security can also be viewed as a 
 * standard assumption on modern hash functions. Note that computational binding follows 
 * from the standard collision resistance assumption. <p>
 * 
 * The pseudo code of this protocol can be found in Protocol 3.6 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class CmtSimpleHashCommitter implements CmtCommitter, SecureCommit {
	
	/*
	 * runs the following protocol:
	 * "Commit phase
	 *		SAMPLE a random value r <- {0, 1}^n
	 *		COMPUTE c = H(r,x) (c concatenated with r)
	 *		SEND c to R
	 *	Decommit phase
	 *		SEND (r, x)  to R
	 *		OUTPUT nothing"	 
	 */
	
	private Channel channel;
	private CryptographicHash hash;
	private int n;
	private SecureRandom random;
	private  Map<Long, CmtSimpleHashCommitmentValues> commitmentMap;

	/**
	 * Constructor that receives a connected channel (to the receiver) and chosses default 
	 * values for the hash function, SecureRandom object and a security parameter n.
	 *  @param channel
	 */
	public CmtSimpleHashCommitter(Channel channel) {
		this(channel, new OpenSSLSHA256(), new SecureRandom(), 32);	
	}
	
	/**
	 * Constructor that receives a connected channel (to the receiver), the hash function
	 * agreed upon between them, a SecureRandom object and a security parameter n.
	 * The Receiver needs to be instantiated with the same hash, otherwise nothing will work properly.
	 * @param channel
	 * @param hash
	 * @param random
	 * @param n security parameter
	 * 
	 */
	public CmtSimpleHashCommitter(Channel channel, CryptographicHash hash, SecureRandom random, int n) {
		this.channel = channel;
		this.hash = hash;
		this.n = n;
		this.random = random;
		commitmentMap = new Hashtable<Long, CmtSimpleHashCommitmentValues>();
		
		//No pre-process in SimpleHash Commitment
	}
	
	/**
	 * Runs the following lines of the commitment scheme:
	 * "SAMPLE a random value r <- {0, 1}^n
	 *	COMPUTE c = H(r,x) (c concatenated with r)".
	 * @return the generated commitment.
	 *	
	 */
	public CmtCCommitmentMsg generateCommitmentMsg(CmtCommitValue input, long id){
		
		if(!(input instanceof CmtByteArrayCommitValue))
			throw new IllegalArgumentException("The input has to be of type CmtByteArrayCommitValue");
		byte[] x = ((CmtByteArrayCommitValue)input).getX();
		//Sample random byte array r
		byte[] r = new byte[n];
		random.nextBytes(r);
		
		//Compute the hash function
		byte[] hashValArray = computeCommitment(x, r);
		
		//After succeeding in sending the commitment, keep the committed value in the map together with its ID.
		commitmentMap.put(Long.valueOf(id), new CmtSimpleHashCommitmentValues(new ByteArrayRandomValue(r), input, hashValArray));
		
		return new CmtSimpleHashCommitmentMessage(hashValArray, id);
	}

	/**
	 * Runs the commit phase of the commitment scheme:
	 * "SAMPLE a random value r <- {0, 1}^n
	 *	COMPUTE c = H(r,x) (c concatenated with r)
	 *	SEND c to R".
	 * @see edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitter#commit(edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitValue, long)
	 */
	public void commit(CmtCommitValue input, long id) throws IOException {
		
		CmtCCommitmentMsg msg = generateCommitmentMsg(input, id);
		try {
			//Send the message by the channel.
			channel.send(msg);
		} catch (IOException e) {
			commitmentMap.remove(Long.valueOf(id));
			throw new IOException("failed to send the message. The error is: " + e.getMessage());
		}	
	}

	/**
	 * Computes the hash function on the concatination of the inputs.
	 * @param x user input
	 * @param r random value
	 * @return the hash result.
	 */
	private byte[] computeCommitment(byte[] x, byte[] r){
		//create an array that will hold the concatenation of r with x
		byte[] c = new byte[n+x.length];
		
		System.arraycopy(r,0, c, 0, r.length);
		System.arraycopy(x, 0, c, r.length, x.length);
		byte[] hashValArray = new byte[hash.getHashedMsgSize()];
		hash.update(c, 0, c.length);
		hash.hashFinal(hashValArray, 0);
		return hashValArray;
	}
	
	@Override
	public CmtCDecommitmentMessage generateDecommitmentMsg(long id){
		
		//fetch the commitment according to the requested ID
		CmtSimpleHashCommitmentValues vals = commitmentMap.get(Long.valueOf(id));
		byte[] x = ((CmtByteArrayCommitValue)vals.getX()).getX();
		return new CmtSimpleHashDecommitmentMessage(vals.getR(), x);
		
	}

	/**
	 * Runs the decommit phase of the commitment scheme:
	 * "SEND (r, x) to R
	 *	OUTPUT nothing."
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
	 * No pre-process is performed for Simple Hash Committer, therefore this function 
	 * returns null! 
	 */
	@Override
	public Object[] getPreProcessValues() {
		return null;
	}

	@Override
	public CmtCommitmentPhaseValues getCommitmentPhaseValues(long id) {
		return commitmentMap.get(id);
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