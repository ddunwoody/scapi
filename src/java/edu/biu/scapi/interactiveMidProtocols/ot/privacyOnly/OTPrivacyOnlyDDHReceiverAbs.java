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
package edu.biu.scapi.interactiveMidProtocols.ot.privacyOnly;

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
import edu.biu.scapi.interactiveMidProtocols.ot.OTRBasicInput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTRInput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTROutput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTRGroupElementQuadMsg;
import edu.biu.scapi.interactiveMidProtocols.ot.OTReceiver;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSMsg;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.securityLevel.DDH;
import edu.biu.scapi.tools.Factories.DlogGroupFactory;

/**
 * Abstract class for OT Privacy assuming DDH receiver.
 * Privacy OT have two modes: one is on ByteArray and the second is on GroupElement.
 * The different is in the input and output types and the way to process them. 
 * In spite that, there is a common behavior for both modes which this class is implementing. <p>
 * 
 * For more information see Protocol 7.2.1 page 179 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell.<p>
 * The pseudo code of this protocol can be found in Protocol 4.2 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
abstract class OTPrivacyOnlyDDHReceiverAbs implements OTReceiver{

	/*	
	 	This class runs the following protocol:
			IF NOT VALID_PARAMS(G,q,g)
	    		REPORT ERROR and HALT
	    	SAMPLE random values alpha, beta, gamma in {0, . . . , q-1} 
			COMPUTE a as follows:
			1.	If sigma = 0 then a = (g^alpha, g^beta, g^(alpha*beta), g^gamma)
			2.	If sigma = 1 then a = (g^alpha, g^beta, g^gamma, g^(alpha*beta))
			SEND a to S
			WAIT for message pairs (w0, c0) and (w1, c1)  from S
			In ByteArray scenario:
				IF  NOT 
					1. w0, w1 in the DlogGroup, AND
					2. c0, c1 are binary strings of the same length
				   REPORT ERROR
				COMPUTE kSigma = (wSigma)^beta
				OUTPUT  xSigma = cSigma XOR KDF(|cSigma|,kSigma)
			In GroupElement scenario:
				IF  NOT 
					1. w0, w1, c0, c1 in the DlogGroup
				   REPORT ERROR
				COMPUTE (kSigma)^(-1) = (wSigma)^(-beta)
				OUTPUT  xSigma = cSigma * (kSigma)^(-1)

	*/	
	
	protected DlogGroup dlog;
	private SecureRandom random;
	private BigInteger qMinusOne; 
	
	/**
	 * Constructor that chooses default values of DlogGroup and SecureRandom.
	 */
	OTPrivacyOnlyDDHReceiverAbs() {
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
	OTPrivacyOnlyDDHReceiverAbs(DlogGroup dlog, SecureRandom random) throws SecurityLevelException, InvalidDlogGroupException{
		
		doConstruct(dlog, random);
	}
	
	/**
	 * Sets the given members.
	 * Runs the following line from the protocol:
	 * "IF NOT VALID_PARAMS(G,q,g)
	 *   		REPORT ERROR and HALT".
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
		// In Zp case, the check is done by Crypto++ library.
		//In elliptic curves case, by default SCAPI uploads a file with NIST recommended curves, 
		//and in this case we assume the parameters are always correct and the validateGroup function always return true.
		//It is also possible to upload a user-defined configuration file. In this case,
		//it is the user's responsibility to check the validity of the parameters by override the implementation of this function.
		if(!dlog.validateGroup())
			throw new InvalidDlogGroupException();
		
		this.dlog = dlog;
		this.random = random;
		qMinusOne =  dlog.getOrder().subtract(BigInteger.ONE);
		
		// This protocol has no pre process stage.
	}
	
	/**
	 * Runs the transfer phase of the OT protocol. <P>
	 * This is the part of the protocol where the receiver input is necessary.<P>
	 * "SAMPLE random values alpha, beta, gamma in {0, . . . , q-1} <P>
	 *	COMPUTE a as follows:<P>
	 *	1.	If sigma = 0 then a = (g^alpha, g^beta, g^(alpha*beta), g^gamma)<P>
	 *	2.	If sigma = 1 then a = (g^alpha, g^beta, g^gamma, g^(alpha*beta))<P>
	 *	SEND a to S<P>
	 *	WAIT for message pairs (w0, c0) and (w1, c1)  from S<P>
	 *	In ByteArray scenario:<P>
	 *		IF  NOT <P>
	 *			1. w0, w1 in the DlogGroup, AND<P>
	 *			2. c0, c1 are binary strings of the same length<P>
	 *			REPORT ERROR<P>
	 *		COMPUTE kSigma = (wSigma)^beta<P>
	 *		OUTPUT  xSigma = cSigma XOR KDF(|cSigma|,kSigma)<P>
	 *	In GroupElement scenario:<P>
	 *		IF  NOT <P>
	 *			1. w0, w1, c0, c1 in the DlogGroup<P>
	 *			REPORT ERROR<P>
	 *		COMPUTE (kSigma)^(-1) = (wSigma)^(-beta)<P>
	 *		OUTPUT  xSigma = cSigma * (kSigma)^(-1)"<P>
	 * 
	 * @return OTROutput, the output of the protocol.
	 */
	public OTROutput transfer(Channel channel, OTRInput input) throws CheatAttemptException, IOException, ClassNotFoundException{
		
		//check if the input is valid.
		//If input is not instance of OTRBasicInput, throw Exception.
		if (!(input instanceof OTRBasicInput)){
			throw new IllegalArgumentException("input should contain sigma.");
		}
		
		byte sigma = ((OTRBasicInput) input).getSigma();
		//The given sigma should be 0 or 1.
		if ((sigma != 0) && (sigma!= 1)){
			throw new IllegalArgumentException("Sigma should be 0 or 1");
		}
		
		//Values required for calculations:
		BigInteger beta = sampleRandomBeta();
		
		//Compute tuple for sender.
		OTRGroupElementQuadMsg a = computeTuple(sigma, beta);
		
		//Send tuple to sender.
		sendTupleToSender(channel, a);
		
		//Wait for message from sender.
		OTSMsg message = waitForMessageFromSender(channel);
		
		//Compute the final calculations to get xSigma.
		return checkMessgeAndComputeX(sigma, beta, message);
		
	}
	
	/**
	 * Samples random beta in [0,...,q-1].
	 * @return the sampled beta.
	 */
	private BigInteger sampleRandomBeta(){
		return BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
	}
	
	/**
	 * Runs the following lines from the protocol:
	 * "SAMPLE random values alpha, gamma in [0, . . . , q-1]
	 * COMPUTE a as follows:
	 *		1.	If sigma = 0 then a = (g^alpha, g^beta, g^(alpha*beta), g^gamma)
	 *		2.	If sigma = 1 then a = (g^alpha, g^beta, g^gamma, g^(alpha*beta))"
	 * @param sigma input of the protocol
	 * @param beta random value sampled by the protocol
	 * @return OTRSemiHonestMessage contains the tuple (h0, h1).
	 */
	private OTRGroupElementQuadMsg computeTuple(byte sigma, BigInteger beta) {

		//Sample random values.
		BigInteger alpha = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		BigInteger gamma = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		
		//Calculates g^alpha, g^beta, g^(alpha*beta), g^gamma.
		GroupElement g = dlog.getGenerator();
		
		GroupElement gAlpha = dlog.exponentiate(g, alpha);
		GroupElement gBeta = dlog.exponentiate(g, beta);
		GroupElement gGamma = dlog.exponentiate(g, gamma);
		GroupElement gAlphaBeta = dlog.exponentiate(g, alpha.multiply(beta));
		
		if (sigma == 0){
			return new OTRGroupElementQuadMsg(gAlpha.generateSendableData(), 
										 gBeta.generateSendableData(), 
										 gAlphaBeta.generateSendableData(), 
										 gGamma.generateSendableData());
		}
		else {
			return new OTRGroupElementQuadMsg(gAlpha.generateSendableData(), 
										 gBeta.generateSendableData(), 
										 gGamma.generateSendableData(), 
										 gAlphaBeta.generateSendableData());
		}
	}
	
	/**
	 * Runs the following line from the protocol:
	 * "SEND a to S"
	 * @param channel 
	 * @param a the tuple to send to the sender.
	 * @throws IOException 
	 */
	private void sendTupleToSender(Channel channel, OTRGroupElementQuadMsg a) throws IOException {
		try {
			channel.send(a);
		} catch (IOException e) {
			throw new IOException("failed to send the message. The thrown message is: " + e.getMessage());
		}
		
	}
	
	/**
	 * Runs the following line from the protocol:
	 * "WAIT for message pairs (w0, c0) and (w1, c1)  from S"
	 * @param channel 
	 * @return OTSMessage contains (w0, c0, w1, c1)
	 * @throws IOException if failed to receive.
	 * @throws ClassNotFoundException
	 */
	private OTSMsg waitForMessageFromSender(Channel channel) throws IOException, ClassNotFoundException {
		Serializable message = null;
		try {
			message =  channel.receive();
		} catch (IOException e) {
			throw new IOException("failed to receive message. The thrown message is: " + e.getMessage());
		}
		if (!(message instanceof OTSMsg)){
			throw new IllegalArgumentException("the given message should be an instance of OTSMessage");
		}
		return (OTSMsg) message;
	}
	
	/**
	 * Runs the following lines from the protocol:
	 * "In ByteArray scenario:
	 *		IF  NOT 
	 *			1. w0, w1 in the DlogGroup, AND
	 *			2. c0, c1 are binary strings of the same length
	 *		   REPORT ERROR
	 *	In GroupElement scenario:
	 *		IF  NOT 
	 *			1. w0, w1, c0, c1 in the DlogGroup
	 *		   REPORT ERROR
	 * In ByteArray scenario:
	 *		COMPUTE kSigma = (wSigma)^beta
	 *		OUTPUT  xSigma = cSigma XOR KDF(|cSigma|,kSigma)
	 *	In GroupElement scenario:
	 *		COMPUTE (kSigma)^(-1) = (wSigma)^(-beta)
	 *		OUTPUT  xSigma = cSigma * (kSigma)^(-1)"
	 *  @param sigma input of the protocol
	 * @param beta random value sampled in the protocol
	 * @param message received from the sender
	 * @return OTROutput contains xSigma
	 * @throws CheatAttemptException 
	 */
	protected abstract OTROutput checkMessgeAndComputeX(byte sigma, BigInteger beta, OTSMsg message) throws CheatAttemptException;
}
