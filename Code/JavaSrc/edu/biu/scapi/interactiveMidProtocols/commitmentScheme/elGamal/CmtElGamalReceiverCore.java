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
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.util.Hashtable;
import java.util.Map;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtRBasicCommitPhaseOutput;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtReceiver;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtRCommitPhaseOutput;
import edu.biu.scapi.midLayer.asymmetricCrypto.encryption.ElGamalEnc;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScElGamalPublicKey;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScElGamalPublicKey.ScElGamalPublicKeySendableData;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.securityLevel.DDH;

/**
 * This abstract class performs all the core functionality of the receiver side of 
 * ElGamal commitment. 
 * Specific implementations can extend this class and add or override functions as necessary.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */

public abstract class CmtElGamalReceiverCore implements CmtReceiver{
	
	/*
	 * runs the following protocol:
	 * "Commit phase
	 *		WAIT for a value c
	 *		STORE c
	 *	Decommit phase
	 *		WAIT for (r, x)  from C
	 *		Let c = (h,u,v); if not of this format, output REJ
	 *		IF NOT
	 *		•	VALID_PARAMS(G,q,g), AND
	 *		•	h <-G, AND
	 *		•	u=g^r 
	 *		•	v = h^r * x
	 *		•	x in G
	 *		      OUTPUT REJ
	 *		ELSE
	 *		      OUTPUT ACC and value x"
	 *
	 */
	
	protected Map<Long , CmtElGamalCommitmentMessage> commitmentMap;
	protected DlogGroup dlog;
	protected Channel channel;
	protected ElGamalEnc elGamal;
	protected ScElGamalPublicKey publicKey;
	
	/**
	 * Constructor that receives a connected channel (to the receiver), 
	 * the DlogGroup agreed upon between them and the encryption object.
	 * The committer needs to be instantiated with the same DlogGroup, 
	 * otherwise nothing will work properly.
	 */
	public CmtElGamalReceiverCore(Channel channel, DlogGroup dlog, ElGamalEnc elGamal) throws SecurityLevelException, InvalidDlogGroupException, ClassNotFoundException, IOException, CheatAttemptException{
		doConstruct(channel, dlog, elGamal);
	}

	// default constructor is not enough since default encryption cannot be chosen.
	protected CmtElGamalReceiverCore(){}

	/**
	 * Sets the given parameters and execute the preprocess phase of the scheme.
	 * @param channel
	 * @param dlog
	 * @param elGamal
	 * @throws SecurityLevelException if the given dlog is not DDH secure
	 * @throws InvalidDlogGroupException if the given dlog is not valid.
	 * @throws ClassNotFoundException if there was a problem during serialization mechanism.
	 * @throws IOException if there was a problem during communication phase
	 * @throws CheatAttemptException it the receiver suspects that the committer is trying to cheat.
	 */
	protected void doConstruct(Channel channel, DlogGroup dlog, ElGamalEnc elGamal) throws SecurityLevelException, InvalidDlogGroupException, ClassNotFoundException, IOException, CheatAttemptException{
		//The underlying dlog group must be DDH secure.
		if (!(dlog instanceof DDH)){
			throw new SecurityLevelException("DlogGroup should have DDH security level");
		}
		if(!dlog.validateGroup())
			throw new InvalidDlogGroupException();

		this.channel = channel;
		this.dlog = dlog;
		commitmentMap = new Hashtable<Long, CmtElGamalCommitmentMessage>();
		this.elGamal = elGamal;
		preProcess();
		try {
			this.elGamal.setKey(publicKey);
		} catch (InvalidKeyException e) {
			//should not occur since the instance of the key is valid.
		}
	}

	/**
	 * The pre-process is performed once within the construction of this object. 
	 * If the user needs to generate new pre-process values then it needs to disregard 
	 * this instance and create a new one.
	 * @throws ClassNotFoundException if there was a problem during serialization mechanism.
	 * @throws IOException if there was a problem during communication phase
	 * @throws CheatAttemptException it the received value h is not in G.
	 */
	private void preProcess() throws ClassNotFoundException, IOException, CheatAttemptException{
		Serializable message = null;
		try {
			message = channel.receive();
		} catch (ClassNotFoundException e) {
			throw new ClassNotFoundException("Failed to receive message. The error is: " + e.getMessage());
		} catch (IOException e) {
			throw new IOException("Failed to receive message. The error is: " + e.getMessage());
		}
		if (!(message instanceof ScElGamalPublicKeySendableData)){
			throw new IllegalArgumentException("The received message should be an instance of OTSMessage");
		}
		ScElGamalPublicKeySendableData publicKeySendableData = (ScElGamalPublicKeySendableData) message;
		this.publicKey = (ScElGamalPublicKey) elGamal.reconstructPublicKey(publicKeySendableData);
		//Set the public key from now on until the end of usage of this instance.
		GroupElement h = publicKey.getH();
		if(!dlog.isMember(h))
			throw new CheatAttemptException("h element is not a member of the current DlogGroup");
	}

	/**
	 * Runs the commit phase of the commitment scheme.<p>
	 * Pseudo code:<p>
	 * "WAIT for a value c<p>
	 *	STORE c".
	 * @return the output of the commit phase.
	 * @throws ClassNotFoundException if there was a problem during serialization mechanism.
	 * @throws IOException  if there was a problem during communication phase
	 */
	public CmtRCommitPhaseOutput receiveCommitment() throws ClassNotFoundException, IOException {
		 CmtElGamalCommitmentMessage msg = null;
		try{
			msg = (CmtElGamalCommitmentMessage) channel.receive();
		} catch (ClassNotFoundException e) {
			throw new ClassNotFoundException("Failed to receive commitment. The error is: " + e.getMessage());
		} catch (IOException e) {
			throw new IOException("Failed to receive commitment. The error is: " + e.getMessage());
		}

		commitmentMap.put(Long.valueOf(msg.getId()), msg);
		return new CmtRBasicCommitPhaseOutput(msg.getId());
	}

	/**
	 * Runs the decommit phase of the commitment scheme.<p>
	 * Pseudo code:<p>
	 * "WAIT for (r, x)  from C<p>
	 *	Let c = (h,u,v); if not of this format, output REJ<p>
	 *	IF NOT<p>
	 *	•	u=g^r <p>
	 *	•	v = h^r * x<p>
	 *	•	x in G<p>
	 *		OUTPUT REJ<p>
	 *	ELSE<p>
	 *	    OUTPUT ACC and value x"
	 * @param id
	 * @return the committed value if the decommit succeeded; null, otherwise.
	 * @throws ClassNotFoundException if there was a problem during serialization mechanism.
	 * @throws IOException  if there was a problem during communication phase
	 * @throws IllegalArgumentException
	 */
	public CmtCommitValue receiveDecommitment(long id) throws ClassNotFoundException, IOException, IllegalArgumentException {
		Serializable message = null;
		try {
			message =  channel.receive();

		} catch (ClassNotFoundException e) {
			throw new ClassNotFoundException("Failed to receive decommitment. The error is: " + e.getMessage());
		} catch (IOException e) {
			throw new IOException("Failed to receive decommitment. The error is: " + e.getMessage());
		}
		if (!(message instanceof CmtElGamalDecommitmentMessage)){
			throw new IllegalArgumentException("the received message is not an instance of CmtElGamalDecommitmentMessage");
		}
		CmtElGamalCommitmentMessage receivedCommitment = commitmentMap.get(Long.valueOf(id));
		
		return verifyDecommitment(receivedCommitment, (CmtElGamalDecommitmentMessage) message);
	}
	
	@Override
	public Object[] getPreProcessedValues(){
		PublicKey[] keys = new PublicKey[1];
		keys[0] = publicKey;
		return keys;
	}
		
	@Override
	public CmtElGamalCommitmentMessage getCommitmentPhaseValues(long id){
		return commitmentMap.get(id);
	}
}
