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
package edu.biu.scapi.interactiveMidProtocols.commitmentScheme.pedersen;

import java.io.IOException;
import java.io.Serializable;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Hashtable;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.generals.ScapiDefaultConfiguration;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.BasicReceiverCommitPhaseOutput;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.BigIntegerCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CTReceiver;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CommitValue;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.securityLevel.DDH;
import edu.biu.scapi.tools.Factories.DlogGroupFactory;

/*
 * This abstract class performs all the core functionality of the receiver side of Pedersen commitment. 
 * Specific implementations can extend this class and add or override functions as necessary.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public abstract class PedersenReceiverCore implements CTReceiver{
	
	/*
	 * runs the following protocol:
	 * "Commit phase
	 *		SAMPLE a random value a <- Zq
	 *		COMPUTE h = g^a
	 *		SEND h to C
	 *		WAIT for message c from C
	 *		STORE values (h,c)
	 *	Decommit phase
	 *		WAIT for (r, x)  from C
	 *		IF  c = g^r * h^x AND x <- Zq
	 *	    	OUTPUT ACC and value x
	 *		ELSE
	 *	        OUTPUT REJ"
	 *
	 */
	
	protected Channel channel;
	protected DlogGroup dlog;
	protected SecureRandom random;
	private BigInteger qMinusOne;
	
	//Sampled random value in Zq that will be the trpadoor.
	protected BigInteger trapdoor ; 	
	
	//h is a value calculated during the creation of this receiver and is sent to the committer once in the beginning.
	protected GroupElement h;  			
	
	//The committer may commit many values one after the other without decommitting. And only at a later time decommit some or all those values. In order to keep track
	//of the commitments and be able to relate them afterwards to the decommitments we keep them in the commitmentMap. The key is some unique id known to the application
	//running the committer. The exact same id has to be use later on to decommit the corresponding values, otherwise the receiver will reject the decommitment.
	private Hashtable<Long, GroupElement> commitmentMap; 
	

	/**
	 * This constructor only needs to get a connected channel (to the committer). All the other needed elements have default values.
	 * If this constructor is used for the recevier then also the default constructor needs to be used by the committer.  
	 */
	protected PedersenReceiverCore(Channel channel) throws IOException{
		String dlogGroupName = ScapiDefaultConfiguration.getInstance().getProperty("DDHDlogGroup");
		try {
			doConstruct(channel, DlogGroupFactory.getInstance().getObject(dlogGroupName) , new SecureRandom());
		} catch (SecurityLevelException e) {
			e.printStackTrace();
		} catch (InvalidDlogGroupException e) {
			e.printStackTrace();
		} catch (FactoriesException e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * Constructor that receives a connected channel (to the committer),the DlogGroup agreed upon between them and a SecureRandom object.
	 * The Committer needs to be instantiated with the same DlogGroup, otherwise nothing will work properly.
	 */
	protected PedersenReceiverCore(Channel channel, DlogGroup dlog, SecureRandom random) throws SecurityLevelException, InvalidDlogGroupException, IOException{
		doConstruct(channel, dlog, random);
	}

	/**
	 * Sets the given parameters and execute the preprocess phase of the scheme.
	 * @param channel
	 * @param dlog
	 * @param random
	 * @throws SecurityLevelException if the given dlog is not DDH secure
	 * @throws InvalidDlogGroupException if the given dlog is not valid.
	 * @throws IOException if there was a problem in the communication
	 */
	private void doConstruct(Channel channel, DlogGroup dlog, SecureRandom random) throws SecurityLevelException, InvalidDlogGroupException, IOException{
		//The underlying dlog group must be DDH secure.
		if (!(dlog instanceof DDH)){
			throw new SecurityLevelException("DlogGroup should have DDH security level");
		}
		//Validate the params of the group.
		if(!dlog.validateGroup())
			throw new InvalidDlogGroupException();

		this.channel = channel;
		this.dlog = dlog;
		this.random = random;
		qMinusOne =  dlog.getOrder().subtract(BigInteger.ONE);
		commitmentMap = new Hashtable<Long, GroupElement>();
		
		//The pre-process phase is actually performed at construction
		preProcess();
	}


	/**
	 * Runs the preprocess stage of the protocol:
	 * "SAMPLE a random value a <- Zq
	 *	COMPUTE h = g^a
	 *	SEND h to C".
	 * The pre-process phase is performed once per instance. 
	 * If different values are required, a new instance of the receiver and the committer 
	 * need to be created.
	 */
	private void preProcess() throws IOException {
		trapdoor = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		h = dlog.exponentiate(dlog.getGenerator(), trapdoor);
		
		CTRPedersenMessage msg = new CTRPedersenMessage(h.generateSendableData());
		try{
			channel.send(msg);
		} catch (IOException e) {
			throw new IOException("failed to send the message. The error is: " + e.getMessage());
		}	
		
	}


	/**
	 * Wait for the committer to send the commitment. When the message is received and 
	 * after reconstructing the group element, save it in the commitmentMap using the id 
	 * also received in the message.
	 * Pseudo code:
	 * "WAIT for message c from C
	 *  STORE values (h,c)".
	 */
	public BasicReceiverCommitPhaseOutput receiveCommitment() throws ClassNotFoundException, IOException {
		Serializable message = null;
		try{
			message = channel.receive();
		} catch (ClassNotFoundException e) {
			throw new ClassNotFoundException("Failed to receive commitment. The error is: " + e.getMessage());
		} catch (IOException e) {
			throw new IOException("Failed to receive commitment. The error is: " + e.getMessage());
		}

		if (!(message instanceof CTCPedersenCommitmentMessage)){
			throw new IllegalArgumentException("The received message should be an instance of CTCPedersenCommitmentMessage");
		}
		CTCPedersenCommitmentMessage msg = (CTCPedersenCommitmentMessage) message;
		GroupElement receivedCommitment = dlog.reconstructElement(true,msg.getCommitment());
		commitmentMap.put(Long.valueOf(msg.getId()), receivedCommitment);
		return new BasicReceiverCommitPhaseOutput(msg.getId());
	}

	/**
	 * Wait for the decommitter to send the decommitment message. 
	 * If there had been a commitment for the requested id then proceed with validation, 
	 * otherwise reject.
	 * 
	 */
	public CommitValue receiveDecommitment(long id) throws ClassNotFoundException, IOException {
		CTCPedersenDecommitmentMessage message = null;
		try {
			message = (CTCPedersenDecommitmentMessage) channel.receive();

		} catch (ClassNotFoundException e) {
			throw new ClassNotFoundException("Failed to receive decommitment. The error is: " + e.getMessage());
		} catch (IOException e) {
			throw new IOException("Failed to receive decommitment. The error is: " + e.getMessage());
		}
		if (!(message instanceof CTCPedersenDecommitmentMessage)){
			throw new IllegalArgumentException("The received message should be an instance of CTCPedersenDecommitmentMessage");
		}
		CTCPedersenDecommitmentMessage msg = (CTCPedersenDecommitmentMessage) message;
		
		return processDecommitment(id, msg.getX(), msg.getR().getR());
	}
	
	/**
	 * Run the decommitment phase of the protocol:
	 * "IF  c = g^r * h^x AND x <- Zq
	 *	    OUTPUT ACC and value x
	 *	ELSE
	 *	    OUTPUT REJ".	
	 * @param id
	 * @param x
	 * @param r
	 * @return
	 */
	protected CommitValue processDecommitment(long id, BigInteger x, BigInteger r) {
		//Calculate c = g^r * h^x
		GroupElement gTor = dlog.exponentiate(dlog.getGenerator(),r);
		GroupElement hTox = dlog.exponentiate(h,x);
		//Fetch received commitment according to ID
		GroupElement receivedCommitment = commitmentMap.get(Long.valueOf(id));
		if (receivedCommitment.equals(dlog.multiplyGroupElements(gTor, hTox)))
			return new BigIntegerCommitValue(x);
		//In the pseudocode it says to return X and ACCEPT if valid commitment else, REJECT.
		//For now we return null as a mode of reject. If the returned value of this function is not null then it means ACCEPT
		return null;
	}

	@Override
	public Object[] getPreProcessedValues(){
		GroupElement[] values = new GroupElement[1];
		values[0] = h;
		return values;
	}
	
	@Override
	public GroupElement getCommitmentPhaseValues(long id){
		return commitmentMap.get(id);
	}
}
