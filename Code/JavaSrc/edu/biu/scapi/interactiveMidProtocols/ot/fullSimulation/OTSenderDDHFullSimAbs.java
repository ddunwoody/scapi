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
package edu.biu.scapi.interactiveMidProtocols.ot.fullSimulation;

import java.io.IOException;
import java.io.Serializable;
import java.security.SecureRandom;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.CommitValueException;
import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.generals.ScapiDefaultConfiguration;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.dh.SigmaDHCommonInput;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.dh.SigmaDHVerifierComputation;
import edu.biu.scapi.interactiveMidProtocols.ot.OTRMessage;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSInput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSMessage;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSender;
import edu.biu.scapi.interactiveMidProtocols.ot.OTUtil;
import edu.biu.scapi.interactiveMidProtocols.ot.OTUtil.RandOutput;
import edu.biu.scapi.interactiveMidProtocols.zeroKnowledge.ZKPOKFromSigmaCommitPedersenVerifier;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.securityLevel.DDH;
import edu.biu.scapi.tools.Factories.DlogGroupFactory;

/**
 * Abstract class for Oblivious transfer based on the DDH assumption that achieves full simulation sender.
 * This implementation can also be used as batch OT that achieves full simulation. In batch oblivious transfer, 
 * the parties run an initialization phase and then can carry out concrete OTs later whenever they have new inputs and wish to carry out an OT. <p>
 * 
 * OT with full simulation has two modes: one is on ByteArray and the second is on GroupElement.
 * The difference is in the input and output types and the way to process them. 
 * In spite that, there is a common behavior for both modes which this class implements.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
abstract class OTSenderDDHFullSimAbs implements OTSender{

	/*	
	  This class runs the following protocol:
		 	IF NOT VALID_PARAMS(G,q,g0)
			        REPORT ERROR and HALT 
			WAIT for message from R
			DENOTE the values received by (g1,h0,h1) 
			Run the verifier in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DH. Use common input (g0,g1,h0,h1/g1).
			If output is REJ, REPORT ERROR (cheat attempt) and HALT
			
			Transfer Phase (with inputs x0,x1)
			WAIT for message from R
			DENOTE the values received by (g,h) 
			COMPUTE (u0,v0) = RAND(g0,g,h0,h)
			COMPUTE (u1,v1) = RAND(g1,g,h1,h)
			in the byte array scenario:
				COMPUTE c0 = x0 XOR KDF(|x0|,v0)
				COMPUTE c1 = x1 XOR KDF(|x1|,v1)
			in the GroupElement scenario:
				COMPUTE c0 = x0 * v0
				COMPUTE c1 = x1 * v1
			SEND (u0,c0) and (u1,c1) to R
			OUTPUT nothing
	 */	 

	protected DlogGroup dlog;
	private SecureRandom random;
	private ZKPOKFromSigmaCommitPedersenVerifier zkVerifier;

	private GroupElement g1, h0, h1; //Pre process values.
	

	/**
	 * Constructor that gets the channel and chooses default values of DlogGroup, ZKPOK and SecureRandom.
	 * @throws CheatAttemptException 
	 * @throws IOException if failed to receive a message during pre process.
	 * @throws ClassNotFoundException 
	 * @throws CommitValueException 
	
	 */
	OTSenderDDHFullSimAbs(Channel channel) throws ClassNotFoundException, IOException, CheatAttemptException, CommitValueException{
		//Read the default DlogGroup name from a configuration file.
		String dlogName = ScapiDefaultConfiguration.getInstance().getProperty("DDHDlogGroup");
		DlogGroup dlog = null;
		try {
			//Create the default DlogGroup by the factory.
			dlog = DlogGroupFactory.getInstance().getObject(dlogName);
		} catch (FactoriesException e1) {
			// Should not occur since the dlog name in the configuration file is valid.
		}
		
		try {
			doConstruct(channel, dlog, new SecureRandom());
		} catch (SecurityLevelException e1) {
			// Should not occur since the dlog in the configuration file is as secure as needed.
		} catch (InvalidDlogGroupException e) {
			// Should not occur since the dlog in the configuration file is valid.
		}
	}

	/**
	 * Constructor that sets the given channel, dlogGroup and random.
	 * @param channel
	 * @param dlog must be DDH secure.
	 * @param random
	 * @throws SecurityLevelException if the given dlog is not DDH secure
	 * @throws InvalidDlogGroupException 
	 * @throws CheatAttemptException 
	 * @throws IOException if failed to receive a message during pre process.
	 * @throws ClassNotFoundException 
	 * @throws CommitValueException 
	 */
	OTSenderDDHFullSimAbs(Channel channel, DlogGroup dlog, SecureRandom random) throws SecurityLevelException, InvalidDlogGroupException, ClassNotFoundException, IOException, CheatAttemptException, CommitValueException{

		doConstruct(channel, dlog, random);
	}

	/**
	 * Sets the given members.
	 * @param channel
	 * @param dlog must be DDH secure.
	 * @param random
	 * @throws SecurityLevelException if the given dlog is not DDH secure.
	 * @throws InvalidDlogGroupException 
	 * @throws CheatAttemptException 
	 * @throws IOException if failed to receive a message during pre process.
	 * @throws ClassNotFoundException 
	 * @throws CommitValueException 
	 */
	private void doConstruct(Channel channel, DlogGroup dlog, SecureRandom random) throws SecurityLevelException, InvalidDlogGroupException, ClassNotFoundException, IOException, CheatAttemptException, CommitValueException {
		//The underlying dlog group must be DDH secure.
		if (!(dlog instanceof DDH)){
			throw new SecurityLevelException("DlogGroup should have DDH security level");
		}
		/* Runs the following part of the protocol:
			IF NOT VALID_PARAMS(G,q,g0)
	        REPORT ERROR and HALT.
	    */
		if(!dlog.validateGroup())
			throw new InvalidDlogGroupException();

		this.dlog = dlog;
		this.random = random;
		
		//read the default statistical parameter used in sigma protocols from a configuration file.
		String statisticalParameter = ScapiDefaultConfiguration.getInstance().getProperty("StatisticalParameter");
		int t = Integer.parseInt(statisticalParameter);
		
		//Create the underlying ZKPOK
		zkVerifier = new ZKPOKFromSigmaCommitPedersenVerifier(channel, new SigmaDHVerifierComputation(dlog, t, random), random);
		
		// Some OT protocols have a pre-process stage before the transfer. 
		// Usually, pre process is done once at the beginning of the protocol and will not be executed later, 
		// and then the transfer function could be called multiple times.
		// We implement the preprocess stage at construction time. 
		// A protocol that needs to call preprocess after the construction time, should create a new instance.
		preProcess(channel);
	}

	/**
	 * Runs the part of the protocol where the sender input is not yet necessary:
	 * WAIT for message from R
	 * DENOTE the values received by (g1,h0,h1) 
	 * Run the verifier in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DH. Use common input (g0,g1,h0,h1/g1).
	 * If output is REJ, REPORT ERROR (cheat attempt) and HALT.
	 * @param channel
	 * @throws IOException if failed to receive a message.
	 * @throws ClassNotFoundException 
	 * @throws CheatAttemptException 
	 * @throws CommitValueException 
	 */
	private void preProcess(Channel channel) throws ClassNotFoundException, IOException, CheatAttemptException, CommitValueException{
		
		//Wait for message from R
		OTRFullSimMessage message = waitForFullSimMessageFromReceiver(channel);
		
		g1 = dlog.reconstructElement(true, message.getG1());
		h0 = dlog.reconstructElement(true, message.getH0());
		h1 = dlog.reconstructElement(true, message.getH1());
		
		//Run the verifier in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DH.
		runZKPOK(g1, h0, h1);
		
	}

	/**
	 * Runs the part of the protocol where the sender's input is necessary as follows:<p>
	 *		Transfer Phase (with inputs x0,x1)
	 *		WAIT for message from R
	 *		DENOTE the values received by (g,h) 
	 *		COMPUTE (u0,v0) = RAND(g0,g,h0,h)
	 *		COMPUTE (u1,v1) = RAND(g1,g,h1,h)
	 *		in the byte array scenario:
	 *			COMPUTE c0 = x0 XOR KDF(|x0|,v0)
	 *			COMPUTE c1 = x1 XOR KDF(|x1|,v1)
	 *		in the GroupElement scenario:
	 *			COMPUTE c0 = x0 * v0
	 *			COMPUTE c1 = x1 * v1
	 *		SEND (u0,c0) and (u1,c1) to R
	 *		OUTPUT nothing<p>
	 * The transfer stage of OT protocol which can be called several times in parallel.
	 * In order to enable the parallel calls, each transfer call should use a different channel to send and receive messages.
	 * This way the parallel executions of the function will not block each other.
	 * The parameters given in the input must match the DlogGroup member of this class, which given in the constructor.
	 * @param channel
	 * @param input 
	 * @throws IOException if failed to send the message.
	 * @throws ClassNotFoundException 
	 */
	public void transfer(Channel channel, OTSInput input) throws IOException, ClassNotFoundException{
		
		//Wait for message from R
		OTRMessage message = waitForMessageFromReceiver(channel);
				
		GroupElement g = dlog.reconstructElement(true, message.getFirstGE());
		GroupElement h = dlog.reconstructElement(true, message.getSecondGE());
		
		//COMPUTE (u0,v0) = RAND(g0,g,h0,h)
		//COMPUTE (u1,v1) = RAND(g1,g,h1,h)
		GroupElement g0 = dlog.getGenerator(); //Get the group generator.
		RandOutput tuple0 = OTUtil.rand(dlog, g0, g, h0, h, random);
		RandOutput tuple1 = OTUtil.rand(dlog, g1, g, h1, h, random);
		GroupElement u0 = tuple0.getU();
		GroupElement v0 = tuple0.getV();
		GroupElement u1 = tuple1.getU();
		GroupElement v1 = tuple1.getV();
		
		//Compute c0, c1.
		OTSMessage tuple = computeTuple(input, u0, u1, v0, v1);
		
		//Send the tuple for the receiver.
		sendTupleToReceiver(channel, tuple);
	
	}

	/**
	 * Runs the following line from the protocol:
	 * "WAIT for message (h0,h1) from R"
	 * @param channel
	 * @return the received message.
	 * @throws ClassNotFoundException 
	 * @throws IOException if failed to receive a message.
	 */
	private OTRFullSimMessage waitForFullSimMessageFromReceiver(Channel channel) throws ClassNotFoundException, IOException{
		Serializable message = null;
		try {
			message = channel.receive();
		} catch (IOException e) {
			throw new IOException("Failed to receive message. The thrown message is: " + e.getMessage());
		}
		if (!(message instanceof OTRFullSimMessage)){
			throw new IllegalArgumentException("The received message should be an instance of OTRFullSimMessage");
		}
		return (OTRFullSimMessage) message;
	}
	
	/**
	 * Runs the following line from the protocol:
	 * "WAIT for message (h0,h1) from R"
	 * @param channel
	 * @return the received message.
	 * @throws ClassNotFoundException 
	 * @throws IOException if failed to receive a message.
	 */
	private OTRMessage waitForMessageFromReceiver(Channel channel) throws ClassNotFoundException, IOException{
		Serializable message = null;
		try {
			message = channel.receive();
		} catch (IOException e) {
			throw new IOException("Failed to receive message. The thrown message is: " + e.getMessage());
		}
		if (!(message instanceof OTRMessage)){
			throw new IllegalArgumentException("The received message should be an instance of OTRMessage");
		}
		return (OTRMessage) message;
	}
	
	/**
	 * Runs the following line from the protocol:
	 * "Run the verifier in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DH. 
	 *  Use common input (g0,g1,h0,h1/g1).
	 *	If output is REJ, REPORT ERROR (cheat attempt) and HALT".
	 * @param g1
	 * @param h0
	 * @param h1
	 * @return the received message.
	 * @throws CheatAttemptException 
	 * @throws IOException if failed to receive a message.
	 * @throws ClassNotFoundException 
	 */
	private void runZKPOK(GroupElement g1, GroupElement h0, GroupElement h1) throws ClassNotFoundException, IOException, CheatAttemptException, CommitValueException {
		GroupElement g1Inv = dlog.getInverse(g1);
		GroupElement h1DivG1 = dlog.multiplyGroupElements(h1, g1Inv);
		
		//If the output of the Zero Knowledge Proof Of Knowledge is REJ, throw CheatAttempException.
		if (!zkVerifier.verify(new SigmaDHCommonInput(g1, h0, h1DivG1))){
			throw new CheatAttemptException("ZKPOK verifier outputed REJECT");
		}
	}

	/**
	 * Runs the following lines from the protocol:
	 * "COMPUTE:
	 * 		in the byte array scenario:
	 *			COMPUTE c0 = x0 XOR KDF(|x0|,v0)
	 *			COMPUTE c1 = x1 XOR KDF(|x1|,v1)
	 *		in the GroupElement scenario:
	 *			COMPUTE c0 = x0 * v0
	 *			COMPUTE c1 = x1 * v1
	 *		SEND (u0,c0) and (u1,c1) to R
	 *		OUTPUT nothing
	 * @param input
	 * @param v1 
	 * @param v0 
	 * @param u1 
	 * @param u0 
	 * @return tuple contains (u, v0, v1) to send to the receiver.
	 */
	protected abstract OTSMessage computeTuple(OTSInput input, GroupElement u0, GroupElement u1, GroupElement v0, GroupElement v1);

	/**
	 * Runs the following lines from the protocol:
	 * "SEND (u0,c0) and (u1,c1) to R"
	 * @param channel
	 * @param message to send to the receiver
	 * @throws IOException if failed to send the message.
	 */
	private void sendTupleToReceiver(Channel channel, OTSMessage message) throws IOException {

		try {
			//Send the message by the channel.
			channel.send(message);
		} catch (IOException e) {
			throw new IOException("failed to send the message. The thrown message is: " + e.getMessage());
		}	
	}

}
