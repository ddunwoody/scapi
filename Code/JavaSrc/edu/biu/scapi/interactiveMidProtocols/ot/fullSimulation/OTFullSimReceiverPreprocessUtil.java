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
import edu.biu.scapi.exceptions.CommitValueException;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.dh.SigmaDHProverInput;
import edu.biu.scapi.interactiveMidProtocols.zeroKnowledge.ZKPOKProver;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;

/**
 * This class execute  the preprocess phase of OT's that achieve full simulation. 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class OTFullSimReceiverPreprocessUtil {

	/**
	 * Runs the preprocess phase of the protocol, where the receiver input is not yet necessary.<p>
	 * 	"SAMPLE random values y, alpha0 <- {0, . . . , q-1} <p>
	 *	SET alpha1 = alpha0 + 1 <p>
	 *	COMPUTE <p>
	 *    1. g1 = (g0)^y<p>
	 *	  2. h0 = (g0)^(alpha0)<p>
	 *	  3. h1 = (g1)^(alpha1)<p>
	 *	SEND (g1,h0,h1) to S<p>
	 *  Run the prover in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DH. Use common input (g0,g1,h0,h1/g1) and private input alpha0."
	 * @param channel
	 * @param dlog
	 * @param zkProver used to prove the ZKPOK_FROM_SIGMA
	 * @param random
	 * @return the values calculated in the preprocess
	 * @throws ClassNotFoundException if there was a problem during the serialization mechanism in the preprocess phase.
	 * @throws CheatAttemptException if the receiver suspects that the sender is trying to cheat in the preprocess phase.
	 * @throws IOException if there was a problem during the communication in the preprocess phase.
	 * @throws CommitValueException can occur in case of ElGamal commitment scheme.
	 */
	public static OTFullSimPreprocessPhaseValues preProcess(DlogGroup dlog, ZKPOKProver zkProver, Channel channel, SecureRandom random) throws IOException, CheatAttemptException, ClassNotFoundException, CommitValueException{
		BigInteger qMinusOne = dlog.getOrder().subtract(BigInteger.ONE);
		
		//Sample random values 
		BigInteger y = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		BigInteger alpha0 = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		
		//Set alpha1 = alpha0 + 1 
		BigInteger alpha1 = alpha0.add(BigInteger.ONE);
		
		//Calculate tuple elements
		GroupElement g0 = dlog.getGenerator();
		GroupElement g1 = dlog.exponentiate(g0, y);
		GroupElement h0 = dlog.exponentiate(g0, alpha0);
		GroupElement h1 = dlog.exponentiate(g1, alpha1);
		
		OTFullSimDDHReceiverMsg tuple = new OTFullSimDDHReceiverMsg(g1.generateSendableData(), h0.generateSendableData(), h1.generateSendableData());
				
		//Send tuple to sender.
		sendTupleToSender(channel, tuple);
		
		//Run the prover in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DH.
		GroupElement g1Inv = dlog.getInverse(g1);
		GroupElement h1DivG1 = dlog.multiplyGroupElements(h1, g1Inv);
		
		zkProver.prove(new SigmaDHProverInput(g1, h0, h1DivG1, alpha0));
		
		return new OTFullSimPreprocessPhaseValues(g0, g1, h0, h1);
	}
	
	
	/**
	 * Runs the following line from the protocol:
	 * "SEND tuple to S"
	 * @param channel
	 * @param a the tuple to send to the sender.
	 * @throws IOException 
	 */
	private static void sendTupleToSender(Channel channel, Serializable a) throws IOException {
		try {
			channel.send(a);
		} catch (IOException e) {
			throw new IOException("failed to send the message. The thrown message is: " + e.getMessage());
		}
		
	}
	
}
