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
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Hashtable;
import java.util.Map;
import java.util.logging.Level;

import edu.biu.scapi.generals.Logging;
import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.BigIntegerRandomValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCCommitmentMsg;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCDecommitmentMessage;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitter;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitValue;
import edu.biu.scapi.midLayer.asymmetricCrypto.encryption.ElGamalEnc;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScElGamalPrivateKey;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScElGamalPublicKey;
import edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertext;
import edu.biu.scapi.midLayer.ciphertext.ElGamalCiphertextSendableData;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.securityLevel.DDH;

/**
 * This abstract class performs all the core functionality of the committer side of 
 * ElGamal commitment. 
 * Specific implementations can extend this class and add or override functions as necessary.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public abstract class CmtElGamalCommitterCore implements CmtCommitter {
	
	/*
	 * runs the following protocol:
	 * "Commit phase
	 *		IF NOT VALID_PARAMS(G,q,g)
	 *			REPORT ERROR and HALT
	 *		SAMPLE random values  a,r <- Zq
	 *		COMPUTE h = g^a
	 *		COMPUTE u = g^r and v = h^r * x
	 *		SEND c = (h,u,v) to R
	 *	Decommit phase
	 *		SEND (r, x)  to R
	 *		OUTPUT nothing"
	 *
	 */
	
	protected Channel channel;
	protected DlogGroup dlog;
	protected SecureRandom random;
	private BigInteger qMinusOne;
	protected Map<Long, CmtElGamalCommitmentPhaseValues> commitmentMap;
	protected ElGamalEnc elGamal;
	protected ScElGamalPublicKey publicKey;
	private ScElGamalPrivateKey privateKey;


	/**
	 * Constructor that receives a connected channel (to the receiver), 
	 * the DlogGroup agreed upon between them, the encryption object and a SecureRandom.
	 * The Receiver needs to be instantiated with the same DlogGroup, 
	 * otherwise nothing will work properly.
	 */
	protected CmtElGamalCommitterCore(Channel channel, DlogGroup dlog, ElGamalEnc elGamal, SecureRandom random) throws SecurityLevelException, InvalidDlogGroupException, IOException{
		doConstruct(channel, dlog, elGamal, random);
	}
	
	// default constructor is not enough since default encryption cannot be chosen.
	protected CmtElGamalCommitterCore() {}

	/**
	 * Sets the given parameters and execute the preprocess phase of the scheme.
	 * @param channel
	 * @param dlog
	 * @param elGamal
	 * @param random
	 * @throws SecurityLevelException if the given dlog is not DDH secure
	 * @throws InvalidDlogGroupException if the given dlog is not valid.
	 * @throws IOException if there was a problem in the communication
	 */
	protected void doConstruct(Channel channel, DlogGroup dlog, ElGamalEnc elGamal, SecureRandom random) throws SecurityLevelException, InvalidDlogGroupException, IOException{
		//The underlying dlog group must be DDH secure.
		if (!(dlog instanceof DDH)){
			throw new SecurityLevelException("DlogGroup should have DDH security level");
		}
		if(!dlog.validateGroup())
			throw new InvalidDlogGroupException();

		this.channel = channel;
		this.dlog = dlog;
		this.random = random;
		qMinusOne =  dlog.getOrder().subtract(BigInteger.ONE);
		commitmentMap = new Hashtable<Long, CmtElGamalCommitmentPhaseValues>();
		this.elGamal = elGamal;
		preProcess();
	}

	/**
	 * The pre-process is performed once within the construction of this object. 
	 * If the user needs to generate new pre-process values then it needs to disregard 
	 * this instance and create a new one.
	 * Runs the following lines from the pseudo code:
	 * "SAMPLE random values  a<- Zq
	 *	COMPUTE h = g^a"
	 * @throws IOException
	 */
	private void preProcess() throws IOException{
		//Instead of sample a and compute h, generate public and private keys directly.
		
		KeyPair pair = elGamal.generateKey();
		//We keep both keys, the private key is used to prove knowledge of this commitment
		//but is not used by the encryption object.
		publicKey = (ScElGamalPublicKey) pair.getPublic();
		privateKey = (ScElGamalPrivateKey) pair.getPrivate();
		try {
			elGamal.setKey(publicKey);
		} catch (InvalidKeyException e) {
			//Catch the exception since it should not happen.
            Logging.getLogger().log(Level.WARNING, "The KeyPair generated by this instance of ElGamal is not valid: " + e.getMessage());
		}
		//Send the public key to the receiver since throughout this connection the same key will be used used for all the commitments.
		try{
			
			channel.send(publicKey.generateSendableData());
		}
		catch (IOException e) {
			throw new IOException("failed to send the public key in the pre-process phase. The error is: " + e.getLocalizedMessage());
		}	
	}
	
	
	/**
	 * Computes the commitment object of the commitment scheme. <p>
	 * Pseudo code:<p>
	 * "SAMPLE random values  r <- Zq <p>
	 *	COMPUTE u = g^r and v = h^r * x". <p>
	 * @return the created commitment.
	 */
	public CmtCCommitmentMsg generateCommitmentMsg(CmtCommitValue input, long id){
		
		//Sample random r <-Zq.
		BigInteger r = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);	
		
		//Compute u = g^r and v = h^r * x.
		//This is actually the encryption of x.
		AsymmetricCiphertext c =  elGamal.encrypt(input.convertToPlaintext(), r);
		
		//keep the committed value in the map together with its ID.
		commitmentMap.put(Long.valueOf(id), new CmtElGamalCommitmentPhaseValues(new BigIntegerRandomValue(r), input,c));
		
		return new CmtElGamalCommitmentMessage((ElGamalCiphertextSendableData)c.generateSendableData(), id);
	}

	/**
	 * Runs the commit phase of the commitment scheme. <p>
	 * Pseudo code:<p>
	 * "SAMPLE random values  r <- Zq <p>
	 *	COMPUTE u = g^r and v = h^r * x <p>
	 *	SEND c = (h,u,v) to R".
	 */
	public void commit(CmtCommitValue input, long id) throws IOException {
		
		//Generate the commitment object
		CmtCCommitmentMsg c = generateCommitmentMsg(input, id);
		
		try {
			//Send the message by the channel.
			channel.send(c);
		} catch (IOException e) {
			commitmentMap.remove(Long.valueOf(id));
			throw new IOException("failed to send the commitment. The error is: " + e.getMessage());
		}	
		
	}
	
	@Override
	public CmtCDecommitmentMessage generateDecommitmentMsg(long id){
		
		//fetch the commitment according to the requested ID
		CmtElGamalCommitmentPhaseValues values = commitmentMap.get(Long.valueOf(id));
		return new CmtElGamalDecommitmentMessage(values.getX().generateSendableData(),values.getR());
	}

	/**
	 * Runs the decommit phase of the commitment scheme.<p>
	 * Pseudo code:<p>
	 * "SEND (r, x)  to R<p>
	 *	OUTPUT nothing"
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

	@Override
	public Key[] getPreProcessValues() {
		Key[] keys = new Key[2];
		keys[0] = publicKey;
		keys[1] = privateKey;
		return keys;
	}

	@Override
	public CmtElGamalCommitmentPhaseValues getCommitmentPhaseValues(long id) {
		return commitmentMap.get(id);
	}

}

