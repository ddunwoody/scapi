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
import java.util.Map;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.generals.ScapiDefaultConfiguration;
import edu.biu.scapi.interactiveMidProtocols.BigIntegerRandomValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtBigIntegerCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCCommitmentMsg;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCDecommitmentMessage;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitter;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitValue;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.securityLevel.DDH;
import edu.biu.scapi.tools.Factories.DlogGroupFactory;

/**
 * This abstract class performs all the core functionality of the committer side of Pedersen commitment. <p>
 * Specific implementations can extend this class and add or override functions as necessary.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public abstract class CmtPedersenCommitterCore implements CmtCommitter{
	
	/*
	 * runs the following protocol:
	 * "Commit phase
	 *		IF NOT VALID_PARAMS(G,q,g)
	 *			REPORT ERROR and HALT
	 *		WAIT for h from R 
	 *		IF NOT h in G
	 *			REPORT ERROR and HALT
	 * 		SAMPLE a random value r <- Zq
	 * 		COMPUTE  c = g^r * h^x
	 * 		SEND c
	 *	Decommit phase
	 *		SEND (r, x) to R
	 *		OUTPUT nothing."
	 *
	 */
	
	protected Channel channel;
	protected DlogGroup dlog;
	protected SecureRandom random;
	private BigInteger qMinusOne;
	
	//The key to the map is an ID and the value is a structure that has the Committer's private input x in Zq,the random value
	//used to commit x and the actual commitment.
	//Each committed value is sent together with an ID so that the receiver can keep it in some data structure. This is necessary
	//in the cases that the same instances of committer and receiver can be used for performing various commitments utilizing the values calculated
	//during the pre-process stage for the sake of efficiency.
	protected Map<Long, CmtPedersenCommitmentPhaseValues> commitmentMap;		
	
	//The content of the message obtained from the receiver during the pre-process phase which occurs upon construction.
    protected GroupElement h; 		 
 
    /**
	 * Constructor that receives a connected channel (to the receiver) and chooses default dlog and random. 
	 * The receiver needs to be instantiated with the default constructor too.
	 */
	protected CmtPedersenCommitterCore(Channel channel) throws ClassNotFoundException, IOException, CheatAttemptException {
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
	 * Constructor that receives a connected channel (to the receiver), the DlogGroup agreed upon between them and a SecureRandom object.
	 * The Receiver needs to be instantiated with the same DlogGroup, otherwise nothing will work properly.
	 */
	protected CmtPedersenCommitterCore(Channel channel, DlogGroup dlog, SecureRandom random) throws IllegalArgumentException, SecurityLevelException, InvalidDlogGroupException, ClassNotFoundException, IOException, CheatAttemptException{
			doConstruct(channel, dlog, random);
	}
	
	/**
	 * Sets the given parameters and execute the preprocess phase of the scheme.
	 * @param channel
	 * @param dlog
	 * @param random
	 * @throws SecurityLevelException if the given dlog is not DDH secure
	 * @throws InvalidDlogGroupException if the given dlog is not valid.
	 * @throws ClassNotFoundException if there was a problem in the serialization
	 * @throws IOException if there was a problem in the communication
	 * @throws CheatAttemptException if the receiver h is not in the DlogGroup.
	 */
	private void doConstruct(Channel channel, DlogGroup dlog, SecureRandom random) throws SecurityLevelException, InvalidDlogGroupException, ClassNotFoundException, IOException, CheatAttemptException{
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
		commitmentMap = new Hashtable<Long, CmtPedersenCommitmentPhaseValues>();
		//The pre-process phase is actually performed at construction
		preProcess();
	}
	
	/**
	 * Runs the preprocess phase of the commitment scheme:
	 * "WAIT for h from R 
	 * IF NOT h in G
	 *	REPORT ERROR and HALT"
	 * @throws ClassNotFoundException if there was a problem in the serialization
	 * @throws IOException if there was a problem in the communication
	 * @throws CheatAttemptException if the receiver h is not in the DlogGroup.
	 */
	private void preProcess() throws ClassNotFoundException, IOException, CheatAttemptException {
		CmtPedersenPreprocessMessage msg = waitForMessageFromReceiver();
		h = dlog.reconstructElement(true, msg.getH());
		if(!dlog.isMember(h))
				throw new CheatAttemptException("h element is not a member of the current DlogGroup");
	}

	/**
	 * Runs the following lines of the commitment scheme: <P>
	 * "SAMPLE a random value r <- Zq<P>
	 * 	COMPUTE  c = g^r * h^x". <p>
	 */
	public CmtCCommitmentMsg generateCommitmentMsg(CmtCommitValue input, long id){
		
		if (!(input instanceof CmtBigIntegerCommitValue))
			throw new IllegalArgumentException("The input must be of type CmtBigIntegerCommitValue");
		
		BigInteger x = ((CmtBigIntegerCommitValue)input).getX();
		//Check that the input is in Zq.
		if ((x.compareTo(BigInteger.ZERO)<0) || (x.compareTo(dlog.getOrder())>0)){
			throw new IllegalArgumentException("The input must be in Zq");
		}
		
		//Sample a random value r <- Zq
		BigInteger r = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);	
		
		//Compute  c = g^r * h^x
		GroupElement gToR = dlog.exponentiate(dlog.getGenerator(), r);
		GroupElement hToX = dlog.exponentiate(h, x);
		GroupElement c = dlog.multiplyGroupElements(gToR, hToX);
		
		//Keep the committed value in the map together with its ID.
		commitmentMap.put(Long.valueOf(id), new CmtPedersenCommitmentPhaseValues(new BigIntegerRandomValue(r), new CmtBigIntegerCommitValue(x), c));
		
		//Send c
		return new CmtPedersenCommitmentMessage(c.generateSendableData(), id);
		
	}
	
	/**
	 * Runs the commit phase of the commitment scheme. <P>
	 * "SAMPLE a random value r <- Zq<P>
	 * 	COMPUTE  c = g^r * h^x<P>
	 * 	SEND c".
	 * @see edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitter#commit(edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitValue, long)
	 */
	public void  commit(CmtCommitValue in, long id) throws IOException, IllegalArgumentException {
		
		CmtCCommitmentMsg msg = generateCommitmentMsg(in, id);
		try {
			//Send the message by the channel.
			channel.send(msg);
		} catch (IOException e) {
			commitmentMap.remove(Long.valueOf(id));
			throw new IOException("failed to send the message. The error is: " + e.getMessage());
		}	
		
	}

	@Override
	public CmtCDecommitmentMessage generateDecommitmentMsg(long id){
		
		CmtPedersenCommitmentPhaseValues values = commitmentMap.get(Long.valueOf(id));
		CmtBigIntegerCommitValue xCVal = (CmtBigIntegerCommitValue)values.getX();
		return new CmtPedersenDecommitmentMessage(xCVal.getX(),values.getR());
		
	}
	
	/**
	 * Runs the decommit phase of the commitment scheme.<P>
	 * "SEND (r, x) to R<P>
	 *	OUTPUT nothing."
	 */
	public void decommit(long id) throws IOException {
		
		//fetch the commitment according to the requested ID
		CmtCDecommitmentMessage msg = generateDecommitmentMsg(id);
		
		try{
			channel.send(msg);
		}
		catch (IOException e) {
			throw new IOException("failed to send the message. The error is: " + e.getMessage());
		}
	}	

	/**
	 * Receives message from the receiver.
	 * @return the received message
	 * @throws ClassNotFoundException if there was a problem during serialization.
	 * @throws IOException if there was a problem in the communication level.
	 */
	private CmtPedersenPreprocessMessage waitForMessageFromReceiver() throws ClassNotFoundException, IOException{
		Serializable message = null;
		try {
			message = channel.receive();
		} catch (ClassNotFoundException e) {
			throw new ClassNotFoundException("Failed to receive message. The error is: " + e.getMessage());
		} catch (IOException e) {
			throw new IOException("Failed to receive message. The error is: " + e.getMessage());
		}
		if (!(message instanceof CmtPedersenPreprocessMessage)){
			throw new IllegalArgumentException("The received message should be an instance of CmtPedersenPreprocessMessage");
		}
		return (CmtPedersenPreprocessMessage) message;
	}
	
	@Override
	public GroupElement[] getPreProcessValues() {
		GroupElement[] values = new GroupElement[1];
		values[0] = h;
		return values;
	}

	@Override
	public CmtPedersenCommitmentPhaseValues getCommitmentPhaseValues(long id) {
		return commitmentMap.get(id);
	}

}

