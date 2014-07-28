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
import edu.biu.scapi.interactiveMidProtocols.BigIntegerRandomValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtBigIntegerCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtByteArrayCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCCommitmentMsg;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCDecommitmentMessage;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitter;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtOnByteArray;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.pedersen.CmtPedersenDecommitmentMessage;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.pedersen.CmtPedersenCommitterCore;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.primitives.hash.openSSL.OpenSSLSHA224;
import edu.biu.scapi.securityLevel.PerfectlyHidingCmt;

/**
 * Concrete implementation of committer that executes the Pedersen hash commitment 
 * scheme in the committer's point of view.<p>
 * 
 * This is a perfectly-hiding commitment that can be used to commit to a value of any length. <p>
 * 
 * For more information see Protocol 6.5.3, page 164 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell.<p>
 * 
 * The pseudo code of this protocol can be found in Protocol 3.2 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class CmtPedersenHashCommitter extends CmtPedersenCommitterCore implements CmtCommitter, PerfectlyHidingCmt, CmtOnByteArray{
	/*
	 * runs the following protocol:
	 * "Run COMMIT_PEDERSEN to commit to value H(x). 
	 * For decommitment, send x and the receiver verifies that the commitment was to H(x). "
	 */
	
	private CryptographicHash hash;
	private Map<Long, byte[]> hashCommitmentMap;
	
	/**
	 * This constructor uses a default Dlog Group and default Cryptographic Hash. They keep the condition that 
	 * the size in bytes of the resulting hash is less than the size in bytes of the order of the DlogGroup.
	 * An established channel has to be provided by the user of the class.
	 * @param channel
	 * @throws CheatAttemptException 
	 * @throws IOException 
	 * @throws ClassNotFoundException 
	 */
	public CmtPedersenHashCommitter(Channel channel) throws ClassNotFoundException, IOException, CheatAttemptException{
		super(channel);
		this.hash = new OpenSSLSHA224(); 	//This default hash suits the default DlogGroup of the underlying Committer.
		hashCommitmentMap = new Hashtable<Long, byte[]>();
	}
	
	/**
	 * This constructor receives as arguments an instance of a Dlog Group and an instance 
	 * of a Cryptographic Hash such that they keep the condition that the size in bytes 
	 * of the resulting hash is less than the size in bytes of the order of the DlogGroup.
	 * Otherwise, it throws IllegalArgumentException.
	 * An established channel has to be provided by the user of the class.
 	 * @param channel an established channel obtained via the Communication Layer 
	 * @param dlog 
	 * @param hash
	 * @param random
	 * @throws IllegalArgumentException if the size in bytes of the resulting hash is bigger than the size in bytes of the order of the DlogGroup
	 * @throws SecurityLevelException if the Dlog Group is not DDH
	 * @throws InvalidDlogGroupException if the parameters of the group do not conform the type the group is supposed to be
	 * @throws CheatAttemptException if the commetter suspects that the receiver is trying to cheat.
	 * @throws IOException if there was a problem during the communication
	 * @throws ClassNotFoundException if there was a problem with the serialization mechanism.
	 */
	public CmtPedersenHashCommitter(Channel channel, DlogGroup dlog, CryptographicHash hash, SecureRandom random) throws IllegalArgumentException, SecurityLevelException, InvalidDlogGroupException, ClassNotFoundException, IOException, CheatAttemptException{
		super(channel,dlog, random);
		if (hash.getHashedMsgSize()> (dlog.getOrder().bitLength()/8)){
			throw new IllegalArgumentException("The size in bytes of the resulting hash is bigger than the size in bytes of the order of the DlogGroup.");
		}
		this.hash = hash;
		hashCommitmentMap = new Hashtable<Long, byte[]>();
	}
	
	/*
	 * We do not provide a constructor that receives a DlogGroup and not a Hash or vice-versa, since they size of the resulting hash has to be less than the order of the group and we cannot 
	 * choose a relevant default for either the group of the hash. 
	 */
	
	/**
	 * Runs COMMIT_ElGamal to commit to value H(x).
	 * @return the created commitment.
	 */
	public CmtCCommitmentMsg generateCommitmentMsg(CmtCommitValue input, long id){
		
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
		
		//After the input has been manipulated with the Hash call the super's commit function. Since the super has been initialized with ScElGamalOnByteArray
		//it will know how to take care of the byte array input.
		return super.generateCommitmentMsg(new CmtBigIntegerCommitValue(new BigInteger(1, hashValArray)), id);
	}

	@Override
	public CmtCDecommitmentMessage generateDecommitmentMsg(long id){
		
		//Fetch the commitment according to the requested ID
		byte[] x = hashCommitmentMap.get(Long.valueOf(id));
		//Get the relevant random value used in the commitment phase
		BigIntegerRandomValue r = (commitmentMap.get(id)).getR();
		
		return new CmtPedersenDecommitmentMessage(new BigInteger(x),r);
	}
	
	/**
	 * Sends x to the receiver.
	 */
	@Override
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
	public CmtCommitValue generateCommitValue(byte[] x) throws CommitValueException {
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