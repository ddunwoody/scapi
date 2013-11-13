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
package edu.biu.scapi.interactiveMidProtocols.sigmaProtocol;

import java.io.IOException;

import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaCommonInput;


/**
 * General interface for Sigma Protocol verifier. Every class that implements it is signed as Sigma Protocol verifier.<p>
 * 
 * Sigma protocols are a basic building block for zero-knowledge, zero-knowledge proofs of knowledge and more. <p>
 * A sigma protocol is a 3-round proof, comprised of a first message from the prover to the verifier, 
 * a random challenge from the verifier and a second message from the prover. <p>
 * See Hazay-Lindell (chapter 6) for more information. 
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public interface SigmaProtocolVerifier {
	
	/**
	 * Runs the verification of this protocol. <p>
	 * This function executes the verification protocol at once by calling the following functions one by one.<p>
	 * This function can be called when a user does not want to save time by doing operations in parallel.
	 * @param input
	 * @return true if the proof has been verified; false, otherwise.
	 * @throws IOException if there was a problem during the communication phase.
	 * @throws ClassNotFoundException if there was a problem during the serialization mechanism.
	 */
	public boolean verify(SigmaCommonInput input) throws ClassNotFoundException, IOException;
	
	/**
	 * Samples the challenge for this protocol.
	 */
	public void sampleChallenge();
	
	/**
	 * Waits for the prover's first message and then sends the chosen challenge to the prover.<p>
	 * This is a blocking function!
	 * @throws IOException if there was a problem during the communication phase.
	 * @throws ClassNotFoundException if there was a problem during the serialization mechanism.
	 */
	public void sendChallenge() throws IOException, ClassNotFoundException;
	
	/**
	 * Waits to the prover's second message and then verifies the proof.	<p>
	 * This is a blocking function!
	 * @param input
	 * @return true if the proof has been verified; false, otherwise.
	 * @throws IOException if there was a problem during the communication phase.
	 * @throws ClassNotFoundException if there was a problem during the serialization mechanism.
	 */
	public boolean processVerify(SigmaCommonInput input) throws ClassNotFoundException, IOException;
	
	/**
	 * Sets the given challenge.
	 * @param challenge
	 */
	public void setChallenge(byte[] challenge);
	
	/**
	 * Returns the sampled challenge.
	 * @return the challenge.
	 */
	public byte[] getChallenge();
}
