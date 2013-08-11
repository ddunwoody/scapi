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
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.dh.SigmaDHProver;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.dh.SigmaDHProverInput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTRBasicInput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTRInput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTROutput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTReceiver;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSMessage;
import edu.biu.scapi.interactiveMidProtocols.zeroKnowledge.ZKPOKFromSigmaPedersenProver;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.cryptopp.CryptoPpDlogZpSafePrime;
import edu.biu.scapi.primitives.dlog.miracl.MiraclDlogECF2m;
import edu.biu.scapi.securityLevel.DDH;

/**
 * Abstract class for Oblivious transfer based on the DDH assumption that achieves full simulation receiver.
 * 
 * OT with one sided simulation have two modes: one is on ByteArray and the second is on GroupElement.
 * The different is in the input and output types and the way to process them. 
 * In spite that, there is a common behavior for both modes which this class is implementing.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public abstract class OTReceiverDDHFullSimAbs implements OTReceiver{

	/*	
	 	This class runs the following protocol:
		 	IF NOT VALID_PARAMS(G,q,g0)
			    REPORT ERROR and HALT
			SAMPLE random values y, alpha0,r <- {0, . . . , q-1} 
			SET alpha1 = alpha0 + 1 
			COMPUTE 
			1.	g1 = (g0)^y
			2.	h0 = (g0)^(alpha0)
			3.	h1 = (g1)^(alpha1)
			4.	g = (gSigma)^r
			5.	h = (hSigma)^r
			SEND (g1,h0,h1) and (g,h) to S
			Run the prover in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DH. Use common input (g0,g1,h0,h1/g1) and private input alpha0.
			WAIT for messages (u0,c0) and (u1,c1) from S
			In ByteArray scenario:
			IF  NOT
			•	u0, u1 in G, AND
			•	c0, c1 are binary strings of the same length
			      REPORT ERROR
			OUTPUT  xSigma = cSigma XOR KDF(|cSigma|,(uSigma)^r)
			In GroupElement scenario:
			IF  NOT
			•	u0, u1, c0, c1 in G
			      REPORT ERROR
			OUTPUT  xSigma = cSigma * (uSigma)^(-r)

	*/	
	
	private Channel channel;
	protected DlogGroup dlog;
	private SecureRandom random;
	private ZKPOKFromSigmaPedersenProver zkProver;
	private BigInteger qMinusOne; 
	
	//Values required for calculations:
	protected short sigma;
	private BigInteger y, alpha0, alpha1;
	protected BigInteger r;
	GroupElement g1, h0, h1, g, h;
	protected GroupElement u0, u1;
	
	/**
	 * Constructor that gets the channel and chooses default values of DlogGroup and SecureRandom.
	 */
	public OTReceiverDDHFullSimAbs(Channel channel) {
		try{
			try {
				//Uses Miracl Koblitz 233 Elliptic curve.
				setMembers(channel, new MiraclDlogECF2m("K-233"), new SecureRandom());
			} catch (IOException e) {
				//If there is a problem with the elliptic curves file, create Zp DlogGroup.
				
					setMembers(channel, new CryptoPpDlogZpSafePrime(), new SecureRandom());
			} catch (IllegalArgumentException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} catch (SecurityLevelException e) {
			// Can not occur since the DlogGroup is DDH secure
		} catch (InvalidDlogGroupException e) {
			// Can not occur since the DlogGroup is valid.
		}
	}
	
	/**
	 * Constructor that sets the given channel, dlogGroup and random.
	 * @param channel
	 * @param dlog must be DDH secure.
	 * @param random
	 * @throws SecurityLevelException if the given dlog is not DDH secure
	 * @throws InvalidDlogGroupException if the given DlogGroup is not valid.
	 */
	public OTReceiverDDHFullSimAbs(Channel channel, DlogGroup dlog, SecureRandom random) throws SecurityLevelException, InvalidDlogGroupException{
		
		setMembers(channel, dlog, random);
	}
	
	/**
	 * Sets the given members.
	 * @param channel
	 * @param dlog must be DDH secure.
	 * @param random
	 * @throws SecurityLevelException if the given dlog is not DDH secure
	 * @throws InvalidDlogGroupException if the given DlogGroup is not valid.
	 */
	private void setMembers(Channel channel, DlogGroup dlog, SecureRandom random) throws SecurityLevelException, InvalidDlogGroupException {
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
		
		this.channel = channel;
		this.dlog = dlog;
		this.random = random;
		//Creates the underlying ZKPOK
		zkProver = new ZKPOKFromSigmaPedersenProver(channel, new SigmaDHProver(dlog, 80, random));
		qMinusOne =  dlog.getOrder().subtract(BigInteger.ONE);
		
	}
	
	/**
	 * Runs the part of the protocol where the receiver input is not yet necessary.
	 */
	public void preProcess(){
		/* Run the following part of the protocol:
			SAMPLE random values y, alpha0,r <- {0, . . . , q-1} 
			SET alpha1 = alpha0 + 1 
			COMPUTE 
			1.	g1 = (g0)^y
			2.	h0 = (g0)^(alpha0)
			3.	h1 = (g1)^(alpha1)
		*/
		
		//Sample random values.
		sampleRandomValues();
		
		//Set alpha1 = alpha0 + 1 
		alpha1 = alpha0.add(BigInteger.ONE);
		
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
				4.	g = (gSigma)^r
				5.	h = (hSigma)^r
			SEND (g1,h0,h1) and (g,h) to S
			Run the prover in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DH. Use common input (g0,g1,h0,h1/g1) and private input alpha0.
			WAIT for messages (u0,c0) and (u1,c1) from S
			In ByteArray scenario:
			IF  NOT
			•	u0, u1 in G, AND
			•	c0, c1 are binary strings of the same length
			      REPORT ERROR
			OUTPUT  xSigma = cSigma XOR KDF(|cSigma|,(uSigma)^r)
			In GroupElement scenario:
			IF  NOT
			•	u0, u1, c0, c1 in G
			      REPORT ERROR
			OUTPUT  xSigma = cSigma * (uSigma)^(-r)
		*/
		
		try{
			//Compute tuple for sender.
			OTRFullSimMessage a = computeTuple();
			
			//Send tuple to sender.
			sendTupleToSender(a);
			
			//Run the prover in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DH.
			runZKPOK();
			
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
	 * "SAMPLE random values y, alpha0,r <- {0, . . . , q-1} ". 
	 */
	private void sampleRandomValues() {
		//Sample random values.
		
		y = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		alpha0 = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		r = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
	}
	
	/**
	 * Runs the following lines from the protocol:
	 * "COMPUTE 
			1.	g1 = (g0)^y
			2.	h0 = (g0)^(alpha0)
			3.	h1 = (g1)^(alpha1)".
	 * These values are necessary to the message tuple
	 */
	private void computeElementsForTuple() {
		GroupElement g0 = dlog.getGenerator();
		
		g1 = dlog.exponentiate(g0, y);
		h0 = dlog.exponentiate(g0, alpha0);
		h1 = dlog.exponentiate(g1, alpha1);
	}
	
	/**
	 * Runs the following lines from the protocol:
	 * "4.	g = (gSigma)^r
	 *	5.	h = (hSigma)^r"
	 * @return OTRFullSimMessage contains the tuple (g1,h0,h1,g,h).
	 */
	private OTRFullSimMessage computeTuple() {

		
		if (sigma == 0){
			g = dlog.exponentiate(dlog.getGenerator(), r);
			h = dlog.exponentiate(h0, r);
		}
		else {
			g = dlog.exponentiate(g1, r);
			h = dlog.exponentiate(h1, r);
		}
		
		return new OTRFullSimMessage(g1.generateSendableData(), h0.generateSendableData(), 
				h1.generateSendableData(), g.generateSendableData(), h.generateSendableData());
	}
	
	/**
	 * Runs the following line from the protocol:
	 * "SEND tuple to S"
	 * @param a the tuple to send to the sender.
	 * @throws IOException 
	 */
	private void sendTupleToSender(OTRFullSimMessage a) throws IOException {
		try {
			channel.send(a);
		} catch (IOException e) {
			throw new IOException("failed to send the message. The thrown message is: " + e.getMessage());
		}
		
	}
	
	/**
	 * Runs the following lines from the protocol:
	 * "Run the prover in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DH. 
	 * Use common input (g0,g1,h0,h1/g1) and private input alpha0."
	 * @throws IOException
	 * @throws CheatAttemptException
	 * @throws ClassNotFoundException
	 */
	private void runZKPOK() throws IOException, CheatAttemptException, ClassNotFoundException {
		GroupElement g1Inv = dlog.getInverse(g1);
		GroupElement h1DivG1 = dlog.multiplyGroupElements(h1, g1Inv);
		
		zkProver.setInput(new SigmaDHProverInput(g1, h0, h1DivG1, alpha0));
		
		zkProver.prove();
	}
	
	/**
	 * Runs the following line from the protocol:
	 * "WAIT for message pairs (w0, c0) and (w1, c1)  from S"
	 * @return OTSMessage contains (w0, c0, w1, c1)
	 * @throws IOException if failed to receive.
	 * @throws ClassNotFoundException
	 */
	private OTSMessage waitForMessageFromSender() throws IOException, ClassNotFoundException {
		Serializable message = null;
		try {
			message =  channel.receive();
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
	 *		OUTPUT  xSigma = cSigma XOR KDF(|cSigma|,(uSigma)^r)
	 *	In GroupElement scenario:
	 *		OUTPUT  xSigma = cSigma * (uSigma)^(-r)"
	 * @return OTROutput contains xSigma
	 */
	protected abstract OTROutput computeFinalXSigma();


}
