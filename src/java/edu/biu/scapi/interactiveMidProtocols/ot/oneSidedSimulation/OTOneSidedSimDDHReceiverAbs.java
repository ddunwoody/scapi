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

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.generals.ScapiDefaultConfiguration;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.dlog.SigmaDlogProverComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.dlog.SigmaDlogProverInput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTRBasicInput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTRInput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTROutput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTRGroupElementQuadMsg;
import edu.biu.scapi.interactiveMidProtocols.ot.OTReceiver;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSMsg;
import edu.biu.scapi.interactiveMidProtocols.zeroKnowledge.ZKPOKFromSigmaCmtPedersenProver;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.securityLevel.DDH;
import edu.biu.scapi.tools.Factories.DlogGroupFactory;

/**
 * Abstract class for OT with one sided simulation receiver.
 * This class is an implementation of Oblivious transfer based on the DDH assumption that achieves 
 * privacy for the case that the sender is corrupted and simulation in the case that the receiver 
 * is corrupted.
 * 
 * OT with one sided simulation have two modes: one is on ByteArray and the second is on GroupElement.
 * The different is in the input and output types and the way to process them. 
 * In spite that, there is a common behavior for both modes which this class is implementing.<P>
 * 
 * For more information see Protocol 7.3 page 185 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell.<p>
 * The pseudo code of this protocol can be found in Protocol 4.3 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
abstract class OTOneSidedSimDDHReceiverAbs implements OTReceiver{

	/*	
	 	This class runs the following protocol:
		 	IF NOT VALID_PARAMS(G,q,g)
	    		REPORT ERROR and HALT
			SAMPLE random values alpha, beta, gamma in {0, . . . , q-1} 
			COMPUTE a as follows:
			1.	If sigma = 0 then a = (g^alpha, g^beta, g^(alpha*beta), g^gamma)
			2.	If sigma = 1 then a = (g^alpha, g^beta, g^gamma, g^(alpha*beta))
			SEND a to S
			Run the prover in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DLOG. Use common input x and private input alpha.
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
	private ZKPOKFromSigmaCmtPedersenProver zkProver;
	private BigInteger qMinusOne; 
	
	/**
	 * Constructor that chooses default values of DlogGroup and SecureRandom.
	 */
	OTOneSidedSimDDHReceiverAbs() {
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
	OTOneSidedSimDDHReceiverAbs(DlogGroup dlog, SecureRandom random) throws SecurityLevelException, InvalidDlogGroupException{
		
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
	 * Runs the transfer phase of the OT protocol.<p>
	 * This is the part of the protocol where the receiver input is necessary.<p>
	 * "SAMPLE random values alpha, beta, gamma in {0, . . . , q-1} <p>
	 *	COMPUTE a as follows:<p>
	 *	1.	If sigma = 0 then a = (g^alpha, g^beta, g^(alpha*beta), g^gamma)<p>
	 *	2.	If sigma = 1 then a = (g^alpha, g^beta, g^gamma, g^(alpha*beta))<p>
	 *	SEND a to S<p>
	 *	Run the prover in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DLOG. Use common input x and private input alpha.<p>
	 *	WAIT for message pairs (w0, c0) and (w1, c1)  from S<p>
	 *	In ByteArray scenario:<p>
	 *		IF  NOT <p>
	 *			1. w0, w1 in the DlogGroup, AND<p>
	 *			2. c0, c1 are binary strings of the same length<p>
	 *			  REPORT ERROR<p>
	 *		COMPUTE kSigma = (wSigma)^beta<p>
	 *		OUTPUT  xSigma = cSigma XOR KDF(|cSigma|,kSigma)<p>
	 *	In GroupElement scenario:<p>
	 *		IF  NOT <p>
	 *			1. w0, w1, c0, c1 in the DlogGroup<p>
	 *			  REPORT ERROR<p>
	 *		COMPUTE (kSigma)^(-1) = (wSigma)^(-beta)<p>
	 *		OUTPUT  xSigma = cSigma * (kSigma)^(-1)"<p>
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
	
		/* Run the following part of the protocol:
			SAMPLE random values alpha, beta, gamma in [0, . . . , q-1] 
			COMPUTE a as follows:
			1.	If sigma = 0 then a = (g^alpha, g^beta, g^(alpha*beta), g^gamma)
			2.	If sigma = 1 then a = (g^alpha, g^beta, g^gamma, g^(alpha*beta))
			SEND a to S
			Run the prover in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DLOG. Use gAlpha and private input alpha.
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
		
		//Sample random values alpha, beta in [0, . . . , q-1]
		BigInteger alpha = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		BigInteger beta = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
				
		//Compute g^alpha
		GroupElement g = dlog.getGenerator();
		GroupElement gAlpha = dlog.exponentiate(g, alpha);
		
		//complete calculations for tuple and create tuple for sender.
		OTRGroupElementQuadMsg a = computeTuple(sigma, alpha, beta, gAlpha);
		
		//Send tuple to sender.
		sendTupleToSender(channel, a);
		
		//Run the prover in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DLOG.
		runZKPOK(channel, gAlpha, alpha);
		
		//Wait for message from sender.
		OTSMsg message = waitForMessageFromSender(channel);
		
		//Compute the final calculations to get xSigma.
		return checkMessgeAndComputeX(sigma, beta, message);	
	}

	/**
	 * Runs the following lines from the protocol:
	 * "COMPUTE a as follows:
	 *			1.	If sigma = 0 then a = (g^alpha, g^beta, g^(alpha*beta), g^gamma)
	 *			2.	If sigma = 1 then a = (g^alpha, g^beta, g^gamma, g^(alpha*beta))"
	 * @param sigma input for the protocol
	 * @param alpha random value sampled in the protocol
	 * @param beta random value sampled in the protocol
	 * @param gAlpha g^alpha
	 * @return OTRPrivacyOnlyMessage contains the tuple (x, y, z0, z1).
	 */
	private OTRGroupElementQuadMsg computeTuple(byte sigma, BigInteger alpha, BigInteger beta, GroupElement gAlpha) {
		//Sample random value gamma in [0, . . . , q-1]
		BigInteger gamma = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		
		//Calculates g^beta, g^(alpha*beta), g^gamma.
		GroupElement g = dlog.getGenerator();
		GroupElement gBeta = dlog.exponentiate(g, beta);
		GroupElement gGamma = dlog.exponentiate(g, gamma);
		GroupElement gAlphaBeta = dlog.exponentiate(g, alpha.multiply(beta));
		
		//Create the tuple.
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
	 * Runs the following lines from the protocol:
	 * "Run the prover in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DLOG. 
	 * Use gAlpha and private input alpha."
	 * @param channel
	 * @param gAlpha 
	 * @param alpha
	 * @throws IOException
	 * @throws CheatAttemptException
	 * @throws ClassNotFoundException
	 */
	private void runZKPOK(Channel channel, GroupElement gAlpha, BigInteger alpha) throws IOException, CheatAttemptException, ClassNotFoundException {
		//read the default statistical parameter used in sigma protocols from a configuration file.
		String statisticalParameter = ScapiDefaultConfiguration.getInstance().getProperty("StatisticalParameter");
		int t = Integer.parseInt(statisticalParameter);
				
		//Creates the underlying ZKPOK
		zkProver = new ZKPOKFromSigmaCmtPedersenProver(channel, new SigmaDlogProverComputation(dlog, t, random));
		
		zkProver.prove(new SigmaDlogProverInput(gAlpha, alpha));
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
	 * @param sigma input of the protocol
	 * @param beta random value sampled in the protocol
	 * @param message received from the sender
	 * @return OTROutput contains xSigma
	 * @throws CheatAttemptException 
	 */
	protected abstract OTROutput checkMessgeAndComputeX(byte sigma, BigInteger beta, OTSMsg message) throws CheatAttemptException;

}
