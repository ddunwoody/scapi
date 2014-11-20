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
package edu.biu.scapi.interactiveMidProtocols.ot.oneSidedSimulation;

import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.logging.Level;

import edu.biu.scapi.generals.Logging;
import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.generals.ScapiDefaultConfiguration;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.dlog.SigmaDlogCommonInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.dlog.SigmaDlogVerifierComputation;
import edu.biu.scapi.interactiveMidProtocols.ot.OTRGroupElementQuadMsg;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSInput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSMsg;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSender;
import edu.biu.scapi.interactiveMidProtocols.zeroKnowledge.ZKPOKFromSigmaCmtPedersenVerifier;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.securityLevel.DDH;
import edu.biu.scapi.tools.Factories.DlogGroupFactory;

/**
 * Abstract class for OT with one sided simulation sender.
 * This class is an implementation of Oblivious transfer based on the DDH assumption that achieves 
 * privacy for the case that the sender is corrupted and simulation in the case that the receiver 
 * is corrupted.
 * 
 * OT with one sided simulation have two modes: one is on ByteArray and the second is on GroupElement.
 * The different is in the input and output types and the way to process them. 
 * In spite that, there is a common behavior for both modes which this class is implementing.<p>
 * 
 * For more information see Protocol 7.3 page 185 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell.<p>
 * The pseudo code of this protocol can be found in Protocol 4.3 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
abstract class OTOneSidedSimDDHSenderAbs implements OTSender{
	/*	
	  This class runs the following protocol:
			IF NOT VALID_PARAMS(G,q,g)
			    REPORT ERROR and HALT
			WAIT for message a from R
			DENOTE the tuple a received by (x, y, z0, z1)
			Run the verifier in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DLOG. Use common input x.
			If output is REJ, REPORT ERROR (cheat attempt) and HALT
			IF NOT
			*	z0 = z1
			*	x, y, z0, z1 in G
			REPORT ERROR (cheat attempt)
			SAMPLE random values u0,u1,v0,v1 <-  {0, . . . , q-1} 
			COMPUTE:
			*	w0 = x^u0 * g^v0
			*	k0 = (z0)^u0 * y^v0
			*	w1 = x^u1 * g^v1
			*	k1 = (z1)^u1 * y^v1 
			*	c0 = x0 XOR KDF(|x0|,k0)
			*	c1 = x1 XOR KDF(|x1|,k1) 
			SEND (w0, c0) and (w1, c1) to R
			OUTPUT nothing

	*/	 

	protected DlogGroup dlog;
	private SecureRandom random;
	private ZKPOKFromSigmaCmtPedersenVerifier zkVerifier;
	private BigInteger qMinusOne;
	
	/**
	 * Constructor that chooses default values of DlogGroup and SecureRandom.
	 */
	OTOneSidedSimDDHSenderAbs(){
		//Read the default DlogGroup name from a configuration file.
		String dlogName = ScapiDefaultConfiguration.getInstance().getProperty("DDHDlogGroup");
		DlogGroup dlog = null;
		try {
			//Create the default DlogGroup by the factory.
			dlog = DlogGroupFactory.getInstance().getObject(dlogName);
            Logging.getLogger().log(Level.FINE, dlog.getGroupType());
		} catch (FactoriesException e1) {
			// Should not occur since the dlog name in the configuration file is valid.
		}
		
		try {
			doConstruct(dlog, new SecureRandom());
		} catch (SecurityLevelException e1) {
			// Should not occur since the dlog in the configuration file is as secure as needed.
		} catch (InvalidDlogGroupException e) {
			// Should not occur since the dlog in the configuration file is valid.
		}
	}
	
	/**
	 * Constructor that sets the given dlogGroup and random.
	 * @param dlog must be DDH secure.
	 * @param random
	 * @throws SecurityLevelException if the given dlog is not DDH secure
	 * @throws InvalidDlogGroupException if the given DlogGroup is not valid.
	 */
	OTOneSidedSimDDHSenderAbs(DlogGroup dlog, SecureRandom random) throws SecurityLevelException, InvalidDlogGroupException{
		
		doConstruct(dlog, random);
	}
	
	/**
	 * Sets the given members.
	 * Runs the following lines from the protocol:
	 * "IF NOT VALID_PARAMS(G,q,g)
			    REPORT ERROR and HALT".
	 * @param dlog must be DDH secure.
	 * @param random
	 * @throws SecurityLevelException if the given dlog is not DDH secure
	 * @throws InvalidDlogGroupException if the given DlogGroup is not valid.
	 */
	private void doConstruct(DlogGroup dlog, SecureRandom random) throws SecurityLevelException, InvalidDlogGroupException {
		//The underlying dlog group must be DDH secure.
		if (!(dlog instanceof DDH)){
			throw new SecurityLevelException("DlogGroup should have DDH security level");
		}
		//Check that the given dlog is valid.
		if(!dlog.validateGroup())
			throw new InvalidDlogGroupException();
		
		this.dlog = dlog;
		this.random = random;
		qMinusOne =  dlog.getOrder().subtract(BigInteger.ONE);
		
		// This protocol has no pre process stage.
		
	}

	/**
	 * Runs the transfer phase of the protocol. <p>
	 * This is the part of the protocol where the sender input is necessary.<p>
	 * "WAIT for message a from R<p>
	 *	DENOTE the tuple a received by (x, y, z0, z1)<p>
	 *	Run the verifier in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DLOG. Use common input x.<p>
	 *	If output is REJ, REPORT ERROR (cheat attempt) and HALT<p>
	 *	IF NOT<p>
	 *	*	z0 = z1<p>
	 *	*	x, y, z0, z1 in G<p>
	 *	REPORT ERROR (cheat attempt)<p>
	 *	SAMPLE random values u0,u1,v0,v1 <-  {0, . . . , q-1} <p>
	 *	COMPUTE:<p>
	 *	*	w0 = x^u0 * g^v0<p>
	 *	*	k0 = (z0)^u0 * y^v0<p>
	 *	*	w1 = x^u1 * g^v1<p>
	 *	*	k1 = (z1)^u1 * y^v1 <p>
	 *	*	c0 = x0 XOR KDF(|x0|,k0)<p>
	 *	*	c1 = x1 XOR KDF(|x1|,k1) <p>
	 *	SEND (w0, c0) and (w1, c1) to R<p>
	 *	OUTPUT nothing"
	 */
	public void transfer(Channel channel, OTSInput input) throws IOException, ClassNotFoundException, CheatAttemptException, InvalidDlogGroupException{
		
		/* Runs the following part of the protocol:
			WAIT for message a from R
			DENOTE the tuple a received by (x, y, z0, z1)
			Run the verifier in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DLOG. Use common input x.
			If output is REJ, REPORT ERROR (cheat attempt) and HALT
			IF NOT
			*	z0 != z1
			*	x, y, z0, z1 in G
			REPORT ERROR (cheat attempt)
			SAMPLE random values u0,u1,v0,v1 <-  {0, . . . , q-1} 
			COMPUTE:
			*	w0 = x^u0 * g^v0
			*	k0 = (z0)^u0 * y^v0
			*	w1 = x^u1 * g^v1
			*	k1 = (z1)^u1 * y^v1 
			COMPUTE: in byteArray scenario:
				*	c0 = x0 XOR KDF(|x0|,k0)
				*	c1 = x1 XOR KDF(|x1|,k1) 
				OR in GroupElement scenario:
				*	c0 = x0 * k0
				*	c1 = x1 * k1
			SEND (w0, c0) and (w1, c1) to R
			OUTPUT nothing
		 */

		//Wait for message a from R
		OTRGroupElementQuadMsg message = waitForMessageFromReceiver(channel);
		
		//Reconstruct the group elements from the given message.
		GroupElement x = dlog.reconstructElement(true, message.getX());
		GroupElement y = dlog.reconstructElement(true, message.getY());
		GroupElement z0 = dlog.reconstructElement(true, message.getZ0());
		GroupElement z1 = dlog.reconstructElement(true, message.getZ1());
				
		//Run the verifier in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DLOG.
		runZKPOK(channel, x);
		
		//If not z0 = z1 and x, y, z0, z1 in G throw CheatAttemptException.
		checkReceivedTuple(x, y, z0, z1);
		
		//Sample random values u0,u1,v0,v1 in  {0, . . . , q-1}
		BigInteger u0 = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		BigInteger u1 = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		BigInteger v0 = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		BigInteger v1 = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		
		//Compute values w0, k0, w1, k1
		GroupElement g = dlog.getGenerator(); //Get the group generator.
		
		//Calculates w0 = x^u0 � g^v0
		GroupElement w0 = dlog.multiplyGroupElements(dlog.exponentiate(x, u0), dlog.exponentiate(g, v0));
		//Calculates k0 = (z0)^u0 � y^v0
		GroupElement k0 = dlog.multiplyGroupElements(dlog.exponentiate(z0, u0), dlog.exponentiate(y, v0));
		
		//Calculates w1 = x^u1 � g^v1
		GroupElement w1 = dlog.multiplyGroupElements(dlog.exponentiate(x, u1), dlog.exponentiate(g, v1));
		//Calculates k1 = (z1)^u1 � y^v1
		GroupElement k1 = dlog.multiplyGroupElements(dlog.exponentiate(z1, u1), dlog.exponentiate(y, v1));
		
		//Compute c0, c1		
		OTSMsg messageToSend = computeTuple(input, w0, w1, k0, k1);
		
		sendTupleToReceiver(channel, messageToSend);
		
	}

	/**
	 * Runs the following line from the protocol:
	 * "WAIT for message (h0,h1) from R"
	 * @param channel 
	 * @return the received message.
	 * @throws IOException if failed to receive a message.
	 * @throws ClassNotFoundException 
	 */
	private OTRGroupElementQuadMsg waitForMessageFromReceiver(Channel channel) throws IOException, ClassNotFoundException{
		Serializable message = null;
		try {
			message = channel.receive();
		} catch (IOException e) {
			throw new IOException("failed to receive message. The thrown message is: " + e.getMessage());
		}
		if (!(message instanceof OTRGroupElementQuadMsg)){
			throw new IllegalArgumentException("the given message should be an instance of OTRPrivacyOnlyMessage");
		}
		return (OTRGroupElementQuadMsg) message;
	}
	
	/**
	 * Runs the following line from the protocol:
	 * "Run the verifier in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DLOG. 
	 *  Use common input x.
	 *	If output is REJ, REPORT ERROR (cheat attempt) and HALT".
	 * @param channel
	 * @param h common input (x)
	 * @return the received message.
	 * @throws CheatAttemptException 
	 * @throws IOException if failed to receive a message.
	 * @throws ClassNotFoundException 
	 * @throws InvalidDlogGroupException 
	 */
	private void runZKPOK(Channel channel, GroupElement h) throws ClassNotFoundException, IOException, CheatAttemptException, InvalidDlogGroupException {
		
		//read the default statistical parameter used in sigma protocols from a configuration file.
		String statisticalParameter = ScapiDefaultConfiguration.getInstance().getProperty("StatisticalParameter");
		int t = Integer.parseInt(statisticalParameter);
				
		//Create the underlying ZKPOK
		zkVerifier = new ZKPOKFromSigmaCmtPedersenVerifier(channel, new SigmaDlogVerifierComputation(dlog, t, random), random);
				
		//If the output of the Zero Knowledge Proof Of Knowledge is REJ, throw CheatAttempException.
		if (!zkVerifier.verify(new SigmaDlogCommonInput(h))){
			throw new CheatAttemptException("ZKPOK verifier outputed REJECT");
		}
	}
	
	/**
	 * Runs the following lines from the protocol:
	 * "IF NOT
	 *	*	z0 != z1
	 *	*	x, y, z0, z1 in the DlogGroup
	 *	REPORT ERROR (cheat attempt)"
	 * @param z1 
	 * @param z0 
	 * @param y 
	 * @param x 
	 * @return the received message.
	 * @throws CheatAttemptException 
	 */
	private void checkReceivedTuple(GroupElement x, GroupElement y, GroupElement z0, GroupElement z1) throws CheatAttemptException {
		
		if (!(dlog.isMember(x))){
			throw new CheatAttemptException("x element is not a member in the current DlogGroup");
		}
		if (!(dlog.isMember(y))){
			throw new CheatAttemptException("y element is not a member in the current DlogGroup");
		}
		if (!(dlog.isMember(z0))){
			throw new CheatAttemptException("z0 element is not a member in the current DlogGroup");
		}
		if (!(dlog.isMember(z1))){
			throw new CheatAttemptException("z1 element is not a member in the current DlogGroup");
		}
		
		if (z0.equals(z1)){
			throw new CheatAttemptException("z0 and z1 are equal");
		}
		
	}
	
	/**
	 * Runs the following lines from the protocol:
	 * "COMPUTE: in byteArray scenario:
	 *	*	c0 = x0 XOR KDF(|x0|,k0)
	 *	*	c1 = x1 XOR KDF(|x1|,k1) 
	 *	OR in GroupElement scenario:
	 *	*	c0 = x0 * k0
	 *	*	c1 = x1 * k1"
	 * @param k1 
	 * @param k0 
	 * @param w1 
	 * @param w0 
	 * @param input 
	 * @return tuple contains (w0, c0, w1, c1) to send to the receiver.
	 */
	protected abstract OTSMsg computeTuple(OTSInput input, GroupElement w0, GroupElement w1, GroupElement k0, GroupElement k1);
		
	/**
	 * Runs the following lines from the protocol:
	 * "SEND (w0, c0) and (w1, c1) to R"
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

