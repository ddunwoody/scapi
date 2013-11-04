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
package edu.biu.scapi.interactiveMidProtocols.ot.fullSimulationROM;

import java.io.IOException;
import java.io.Serializable;
import java.security.SecureRandom;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.generals.ScapiDefaultConfiguration;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.dh.SigmaDHCommonInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.dh.SigmaDHVerifierComputation;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSInput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSMsg;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSender;
import edu.biu.scapi.interactiveMidProtocols.ot.OTUtil;
import edu.biu.scapi.interactiveMidProtocols.ot.OTUtil.RandOutput;
import edu.biu.scapi.interactiveMidProtocols.zeroKnowledge.ZKPOKFiatShamirCommonInput;
import edu.biu.scapi.interactiveMidProtocols.zeroKnowledge.ZKPOKFiatShamirFromSigmaVerifier;
import edu.biu.scapi.interactiveMidProtocols.zeroKnowledge.ZKPOKFiatShamirProof;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.randomOracle.RandomOracle;
import edu.biu.scapi.securityLevel.DDH;
import edu.biu.scapi.tools.Factories.DlogGroupFactory;
import edu.biu.scapi.tools.Factories.RandomOracleFactory;

/**
 * Abstract class for the sender in oblivious transfer protocol, based on the DDH assumption 
 * that achieves full simulation in the random oracle model.
 * 
 * OT with full simulation in the random oracle model has two modes: one is on ByteArray and the 
 * second is on GroupElement.
 * The difference is in the input and output types and the way to process them. 
 * In spite that, there is a common behavior for both modes which this class implements.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
abstract class OTFullSimROMDDHSenderAbs implements OTSender{
	
	/*	
	  This class runs the following protocol:
		 	IF NOT VALID_PARAMS(G,q,g0)
         		REPORT ERROR and HALT
			Verify tP using common input (g0,g1,h0,h1/g1).
			If verifier-output is REJ, REPORT ERROR (cheat attempt) and HALT
			COMPUTE (u0,v0) = RAND(g0,g,h0,h)
			COMPUTE (u1,v1) = RAND(g1,g,h1,h)
			in byte array mode:
				COMPUTE c0 = x0 XOR KDF(|x0|,v0)
				COMPUTE c1 = x1 XOR KDF(|x1|,v1)
			in group element mode:
				COMPUTE c0 = x0 * v0
				COMPUTE c1 = x1 * v1
			SEND (u0,c0) and (u1,c1) to R
			OUTPUT nothing

	 */	 

	protected DlogGroup dlog;
	private SecureRandom random;
	private ZKPOKFiatShamirFromSigmaVerifier zkVerifier;
	private RandomOracle ro;
	int t; 													//Statistical parameter.

	/**
	 * Constructor that chooses default values of DlogGroup, ZKPOK and SecureRandom.
	 * 
	
	 */
	OTFullSimROMDDHSenderAbs() {
		//Read the default DlogGroup name from a configuration file.
		String dlogName = ScapiDefaultConfiguration.getInstance().getProperty("DDHDlogGroup");
		String roName = ScapiDefaultConfiguration.getInstance().getProperty("RandomOracle");
		DlogGroup dlog = null;
		RandomOracle ro = null;
		try {
			//Create the default DlogGroup by the factory.
			dlog = DlogGroupFactory.getInstance().getObject(dlogName);
			//Create the default random oracle by the factory.
			ro = RandomOracleFactory.getInstance().getObject(roName);
		} catch (FactoriesException e1) {
			// Should not occur since the dlog name in the configuration file is valid.
		}
		
		
		try {
			doConstruct(dlog, ro, new SecureRandom());
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
	 * @throws InvalidDlogGroupException 
	 * @throws SecurityLevelException 
	 * 
	 */
	OTFullSimROMDDHSenderAbs(DlogGroup dlog, RandomOracle oracle, SecureRandom random) throws SecurityLevelException, InvalidDlogGroupException {

		doConstruct(dlog, oracle, random);
	}

	/**
	 * Sets the given members.
	 * @param dlog must be DDH secure.
	 * @param randomOracle
	 * @param random
	 * @throws SecurityLevelException 
	 * @throws InvalidDlogGroupException 
	 * 
	 */
	private void doConstruct(DlogGroup dlog, RandomOracle oracle, SecureRandom random) throws SecurityLevelException, InvalidDlogGroupException  {
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
		this.ro = oracle;
		
		//read the default statistical parameter used in sigma protocols from a configuration file.
		String statisticalParameter = ScapiDefaultConfiguration.getInstance().getProperty("StatisticalParameter");
		t = Integer.parseInt(statisticalParameter);
		
		// This OT protocol has no pre process stage.
	}

	/**
	 * Runs the part of the protocol where the sender's input is necessary as follows:<p>
	 *		Let tP denote the resulting proof transcript.
	 *		Verify tP using common input (g0,g1,h0,h1/g1).
	 *		If verifier-output is REJ, REPORT ERROR (cheat attempt) and HALT
	 *		COMPUTE (u0,v0) = RAND(g0,g,h0,h)
	 *		COMPUTE (u1,v1) = RAND(g1,g,h1,h)
	 *		COMPUTE c0 = x0 XOR KDF(|x0|,v0)
	 *		COMPUTE c1 = x1 XOR KDF(|x1|,v1)
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
	 * @throws CheatAttemptException 
	 * @throws InvalidDlogGroupException 
	 */
	public void transfer(Channel channel, OTSInput input) throws IOException, ClassNotFoundException, InvalidDlogGroupException, CheatAttemptException{
		//Wait for message from R
		OTFullSimROMDDHReceiverMsg message = waitForMsgFromReceiver(channel);
		
		GroupElement g1 = dlog.reconstructElement(true, message.getG1());
		GroupElement h0 = dlog.reconstructElement(true, message.getH0());
		GroupElement h1 = dlog.reconstructElement(true, message.getH1());
		GroupElement g = dlog.reconstructElement(true, message.getG());
		GroupElement h = dlog.reconstructElement(true, message.getH());
		ZKPOKFiatShamirProof proof = message.getProof();
		
		//Run the verifier in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DH.
		runZKPOK(channel, g1, h0, h1, proof);
		
		
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
		OTSMsg tuple = computeTuple(input, u0, u1, v0, v1);
		
		//Send the tuple for the receiver.
		sendTupleToReceiver(channel, tuple);
	
	}

	/**
	 * Receives message from the verifier.
	 * @param channel
	 * @return the received message.
	 * @throws ClassNotFoundException 
	 * @throws IOException if failed to receive a message.
	 * @throws IllegalArgumentException if the received message is i=not an instance of OTFullSimROMDDHReceiverMsg.
	 */
	private OTFullSimROMDDHReceiverMsg waitForMsgFromReceiver(Channel channel) throws ClassNotFoundException, IOException{
		Serializable message = null;
		try {
			message = channel.receive();
		} catch (IOException e) {
			throw new IOException("Failed to receive message. The thrown message is: " + e.getMessage());
		}
		if (!(message instanceof OTFullSimROMDDHReceiverMsg)){
			throw new IllegalArgumentException("The received message should be an instance of OTFullSimROMDDHReceiverMsg");
		}
		return (OTFullSimROMDDHReceiverMsg) message;
	}
	
	
	/**
	 * Runs the following line from the protocol:
	 * "Let tP denote the resulting proof transcript.
	 *	Verify tP using common input (g0,g1,h0,h1/g1).
	 *	If verifier-output is REJ, REPORT ERROR (cheat attempt) and HALT".
	 * @param g1
	 * @param h0
	 * @param h1
	 * @param g
	 * @param h
	 * @param proof
	 * @throws InvalidDlogGroupException 
	 * @throws CheatAttemptException 
	 * @throws IOException 
	 * 
	 */
	private void runZKPOK(Channel channel, GroupElement g1, GroupElement h0, GroupElement h1, ZKPOKFiatShamirProof proof) throws InvalidDlogGroupException, CheatAttemptException, IOException  {
		
		//Create the underlying ZKPOK
		zkVerifier = new ZKPOKFiatShamirFromSigmaVerifier(channel, new SigmaDHVerifierComputation(dlog, t, random), ro);
				
		GroupElement g1Inv = dlog.getInverse(g1);
		GroupElement h1DivG1 = dlog.multiplyGroupElements(h1, g1Inv);
		
		ZKPOKFiatShamirCommonInput input = new ZKPOKFiatShamirCommonInput(new SigmaDHCommonInput(g1, h0, h1DivG1));
		
		//If the output of the Zero Knowledge Proof Of Knowledge is REJ, throw CheatAttempException.
		if (!zkVerifier.verifyFiatShamirProof(input, proof)){
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
	protected abstract OTSMsg computeTuple(OTSInput input, GroupElement u0, GroupElement u1, GroupElement v0, GroupElement v1);

	/**
	 * Runs the following lines from the protocol:
	 * "SEND (u0,c0) and (u1,c1) to R"
	 * @param channel
	 * @param message to send to the receiver
	 * @throws IOException if failed to send the message.
	 */
	private void sendTupleToReceiver(Channel channel, OTSMsg message) throws IOException {

		try {
			//Send the message by the channel.
			channel.send(message);
		} catch (IOException e) {
			throw new IOException("failed to send the message. The thrown message is: " + e.getMessage());
		}	
	}

}
