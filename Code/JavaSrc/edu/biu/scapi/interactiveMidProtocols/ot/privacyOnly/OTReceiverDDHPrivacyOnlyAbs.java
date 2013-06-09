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

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.interactiveMidProtocols.ot.OTRBasicInput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTRInput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTROutput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTReceiver;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSMessage;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.cryptopp.CryptoPpDlogZpSafePrime;
import edu.biu.scapi.primitives.dlog.miracl.MiraclDlogECF2m;
import edu.biu.scapi.securityLevel.DDH;

/**
 * Abstract class for OT Privacy assuming DDH receiver.
 * Privacy OT have two modes: one is on ByteArray and the second is on GroupElement.
 * The different is in the input and output types and the way to process them. 
 * In spite that, there is a common behavior for both modes which this class is implementing.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public abstract class OTReceiverDDHPrivacyOnlyAbs implements OTReceiver{

	/*	
	 	This class runs the following protocol:
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
	
	private Channel channel;
	protected DlogGroup dlog;
	private SecureRandom random;
	private BigInteger qMinusOne; 
	
	//Values required for calculations:
	protected short sigma;
	private BigInteger alpha, gamma;
	protected BigInteger beta;
	private GroupElement gAlpha, gBeta, gGamma, gAlphaBeta;
	protected GroupElement w0, w1;
	
	/**
	 * Constructor that gets the channel and chooses default values of DlogGroup and SecureRandom.
	 */
	public OTReceiverDDHPrivacyOnlyAbs(Channel channel){
		try {
			//Uses Miracl Koblitz 233 Elliptic curve.
			setMembers(channel, new MiraclDlogECF2m("K-233"), new SecureRandom());
		} catch (IOException e) {
			//If there is a problem with the elliptic curves file, create Zp DlogGroup.
			setMembers(channel, new CryptoPpDlogZpSafePrime(), new SecureRandom());
		}
	}
	
	/**
	 * Constructor that sets the given channel, dlogGroup and random.
	 * @param channel
	 * @param dlog must be DDH secure.
	 * @param random
	 */
	public OTReceiverDDHPrivacyOnlyAbs(Channel channel, DlogGroup dlog, SecureRandom random){
		
		setMembers(channel, dlog, random);
	}
	
	/**
	 * Sets the given members.
	 * @param channel
	 * @param dlog must be DDH secure.
	 * @param random
	 * @throws IllegalArgumentException if the given dlog is not DDH secure or if it is not valid.
	 */
	private void setMembers(Channel channel, DlogGroup dlog, SecureRandom random) {
		//The underlying dlog group must be DDH secure.
		if (!(dlog instanceof DDH)){
			throw new IllegalArgumentException("DlogGroup should have DDH security level");
		}
		//Check that the given dlog is valid.
		// In Zp case, the check is done by Crypto++ library.
		//In elliptic curves case, by default SCAPI uploads a file with NIST recommended curves, 
		//and in this case we assume the parameters are always correct and the validateGroup function always return true.
		//It is also possible to upload a user-defined configuration file. In this case,
		//it is the user's responsibility to check the validity of the parameters by override the implementation of this function.
		if (!(dlog.validateGroup())){
			throw new IllegalArgumentException("the given DlogGroup is not valid");
		}
		
		this.channel = channel;
		this.dlog = dlog;
		this.random = random;
		qMinusOne =  dlog.getOrder().subtract(BigInteger.ONE);
		
	}
	
	/**
	 * Runs the part of the protocol where the receiver input is not yet necessary.
	 */
	public void preProcess(){
		/* Run the following part of the protocol:
				SAMPLE random values alpha, beta, gamma in [0, . . . , q-1] 
				COMPUTE:
				g^alpha, g^beta, g^(alpha*beta), g^gamma.
		*/
		
		//Sample random values.
		sampleRandomValues();
		
		//Calculate tuple elements
		computeElementsForTuple();
	}

	/**
	 * Sets the input for this OT receiver.
	 * @param input MUST be OTRBasicInput.
	 */
	public void setInput(OTRInput input) {
		//If input is not instance of OTRBasicInput, throw Exception.
		if (!(input instanceof OTRBasicInput)){
			throw new IllegalArgumentException("input shoud contain sigma.");
		}
		
		//The given sigma should be 0 or 1.
		if ((sigma != 0) && (sigma!= 1)){
			throw new IllegalArgumentException("Sigma should be 0 or 1");
		}
		//Set sigma.
		this.sigma = ((OTRBasicInput) input).getSigma();
	}
	
	/**
	 * Runs the part of the protocol where the receiver input is necessary.
	 * @return OTROutput, the output of the protocol.
	 * @throws CheatAttemptException if there was a cheat attempt during the execution of the protocol.
	 * @throws IOException if the send or receive functions failed.
	 * @throws ClassNotFoundException if the receive failed.
	 */
	public OTROutput transfer() throws CheatAttemptException, IOException, ClassNotFoundException{
		/* Run the following part of the protocol:
				COMPUTE a as follows:
				1.	If  sigma = 0 then a = (g^alpha, g^beta, g^(alpha*beta), g^gamma)
				2.	If  sigma = 1 then a = (g^alpha, g^beta, g^gamma, g^(alpha*beta))
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
		
		try{
			//Compute tuple for sender.
			OTRPrivacyMessage a = computeTuple();
			
			//Send tuple to sender.
			sendTupleToSender(a);
			
			//Wait for message from sender.
			OTSMessage message = waitForMessageFromSender();
			
			//checked the received message.
			checkReceivedTuple(message);
			
			//Compute the final calculations to get xSigma.
			return computeFinalXSigma();
			
		}catch(NullPointerException e){
			throw new IllegalStateException("preProcess function should be called before transfer atleast once");
		}
		
		
	}

	/**
	 * Runs the following line from the protocol:
	 * "SAMPLE random values alpha, beta, gamma in [0, . . . , q-1]". 
	 */
	private void sampleRandomValues() {
		//Sample random values.
		
		alpha = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		beta = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		gamma = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
	}
	
	/**
	 * Calculates g^alpha, g^beta, g^(alpha*beta), g^gamma.
	 * These values are necessary to the message tuple
	 */
	private void computeElementsForTuple() {
		GroupElement g = dlog.getGenerator();
		
		gAlpha = dlog.exponentiate(g, alpha);
		gBeta = dlog.exponentiate(g, beta);
		gGamma = dlog.exponentiate(g, gamma);
		gAlphaBeta = dlog.exponentiate(g, alpha.multiply(beta));
		
	}
	
	/**
	 * Runs the following lines from the protocol:
	 * "COMPUTE a as follows:
	 *			1.	If sigma = 0 then a = (g^alpha, g^beta, g^(alpha*beta), g^gamma)
				2.	If sigma = 1 then a = (g^alpha, g^beta, g^gamma, g^(alpha*beta))"
	 * @return OTRSemiHonestMessage contains the tuple (h0, h1).
	 */
	private OTRPrivacyMessage computeTuple() {

		if (sigma == 0){
			return new OTRPrivacyMessage(gAlpha.generateSendableData(), 
										 gBeta.generateSendableData(), 
										 gAlphaBeta.generateSendableData(), 
										 gGamma.generateSendableData());
		}
		else {
			return new OTRPrivacyMessage(gAlpha.generateSendableData(), 
										 gBeta.generateSendableData(), 
										 gGamma.generateSendableData(), 
										 gAlphaBeta.generateSendableData());
		}
	}
	
	/**
	 * Runs the following line from the protocol:
	 * "SEND a to S"
	 * @param a the tuple to send to the sender.
	 * @throws IOException 
	 */
	private void sendTupleToSender(OTRPrivacyMessage a) throws IOException {
		try {
			channel.send(a);
		} catch (IOException e) {
			throw new IOException("failed to send the message. The thrown message is: " + e.getMessage());
		}
		
	}
	
	/**
	 * Runs the following line from the protocol:
	 * "WAIT for message pairs (w0, c0) and (w1, c1)  from S"
	 * @return OTSMessage contains (w0, c0, w1, c1)
	 * @throws IOException if failed to receive.
	 * @throws ClassNotFoundException if failed to receive.
	 */
	private OTSMessage waitForMessageFromSender() throws IOException, ClassNotFoundException {
		Serializable message = null;
		try {
			message =  channel.receive();
		} catch (ClassNotFoundException e) {
			throw new ClassNotFoundException("failed to receive message. The thrown message is: " + e.getMessage());
		} catch (IOException e) {
			throw new IOException("failed to receive message. The thrown message is: " + e.getMessage());
		}
		if (!(message instanceof OTSMessage)){
			throw new IllegalArgumentException("the given message should be an instance of OTSMessage");
		}
		return (OTSMessage) message;
	}
	
	/**
	 * Runs the following line from the protocol:
	 * "In ByteArray scenario:
	 *		IF  NOT 
	 *			1. w0, w1 in the DlogGroup, AND
	 *			2. c0, c1 are binary strings of the same length
	 *		   REPORT ERROR
	 *	In GroupElement scenario:
	 *		IF  NOT 
	 *			1. w0, w1, c0, c1 in the DlogGroup
	 *		   REPORT ERROR"		
	 * @param message
	 * @throws CheatAttemptException 
	 */
	protected abstract void checkReceivedTuple(OTSMessage message) throws CheatAttemptException;
	
	/**
	 * Runs the following lines from the protocol:
	 * "In ByteArray scenario:
	 *		COMPUTE kSigma = (wSigma)^beta
	 *		OUTPUT  xSigma = cSigma XOR KDF(|cSigma|,kSigma)
	 *	In GroupElement scenario:
	 *		COMPUTE (kSigma)^(-1) = (wSigma)^(-beta)
	 *		OUTPUT  xSigma = cSigma * (kSigma)^(-1)"
	 * @return OTROutput contains xSigma
	 */
	protected abstract OTROutput computeFinalXSigma();
}
