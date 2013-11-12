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

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.CommitValueException;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.dh.SigmaDHCommonInput;
import edu.biu.scapi.interactiveMidProtocols.zeroKnowledge.ZKPOKVerifier;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;

/**
 * This class execute  the preprocess phase of OT's that achieve full simulation. 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class OTFullSimSenderPreprocessUtil {

	/**
	 * Runs the preprocess phase of the OT protocol, where the sender input is not yet necessary.<p>
	 * "WAIT for message from R<p>
	 * DENOTE the values received by (g1,h0,h1) <p>
	 * Run the verifier in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DH. Use common input (g0,g1,h0,h1/g1).<p>
	 * If output is REJ, REPORT ERROR (cheat attempt) and HALT."<p>
	 * @param channel used to communicate between the parties.
	 * @param dlog
	 * @param zkVerifier used to verify the ZKPOK_FROM_SIGMA
	 * @return the values calculated in the preprocess
	 * @throws ClassNotFoundException if there was a problem during the serialization mechanism in the preprocess phase.
	 * @throws CheatAttemptException if the sender suspects that the receiver is trying to cheat in the preprocess phase.
	 * @throws IOException if there was a problem during the communication in the preprocess phase.
	 * @throws CommitValueException can occur in case of ElGamal commitment scheme.
	 */
	public static OTFullSimPreprocessPhaseValues preProcess(Channel channel, DlogGroup dlog, ZKPOKVerifier zkVerifier) throws ClassNotFoundException, IOException, CheatAttemptException, CommitValueException{
		
		//Wait for message from R
		OTFullSimDDHReceiverMsg message = waitForFullSimMessageFromReceiver(channel);
		
		GroupElement g1 = dlog.reconstructElement(true, message.getG1());
		GroupElement h0 = dlog.reconstructElement(true, message.getH0());
		GroupElement h1 = dlog.reconstructElement(true, message.getH1());
		
		//Run the verifier in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DH.
		GroupElement g1Inv = dlog.getInverse(g1);
		GroupElement h1DivG1 = dlog.multiplyGroupElements(h1, g1Inv);
		
		//If the output of the Zero Knowledge Proof Of Knowledge is REJ, throw CheatAttempException.
		if (!zkVerifier.verify(new SigmaDHCommonInput(g1, h0, h1DivG1))){
			throw new CheatAttemptException("ZKPOK verifier outputed REJECT");
		}
		
		return new OTFullSimPreprocessPhaseValues(dlog.getGenerator(), g1, h0, h1);
	}
	
	/**
	 * Runs the following line from the protocol:
	 * "WAIT for message (h0,h1) from R"
	 * @param channel
	 * @return the received message.
	 * @throws ClassNotFoundException 
	 * @throws IOException if failed to receive a message.
	 */
	private static OTFullSimDDHReceiverMsg waitForFullSimMessageFromReceiver(Channel channel) throws ClassNotFoundException, IOException{
		Serializable message = null;
		try {
			message = channel.receive();
		} catch (IOException e) {
			throw new IOException("Failed to receive message. The thrown message is: " + e.getMessage());
		}
		if (!(message instanceof OTFullSimDDHReceiverMsg)){
			throw new IllegalArgumentException("The received message should be an instance of OTRFullSimMessage");
		}
		return (OTFullSimDDHReceiverMsg) message;
	}
	
}
