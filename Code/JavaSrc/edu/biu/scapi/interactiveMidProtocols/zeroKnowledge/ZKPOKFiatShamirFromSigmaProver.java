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
package edu.biu.scapi.interactiveMidProtocols.zeroKnowledge;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaProverComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProtocolMsg;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProverInput;
import edu.biu.scapi.primitives.randomOracle.HKDFBasedRO;
import edu.biu.scapi.primitives.randomOracle.RandomOracle;

/**
 * Concrete implementation of Zero Knowledge prover.
 * 
 * This is a transformation that takes any Sigma protocol and a random oracle 
 * (instantiated with any hash function) H and yields a zero-knowledge proof of knowledge.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ZKPOKFiatShamirFromSigmaProver implements ZKPOKProver{

	private Channel channel;
	private SigmaProverComputation sProver; //Underlying prover that computes the proof of the sigma protocol.
	private RandomOracle ro;				//Underlying random oracle to use.
	
	/**
	 * Constructor that accepts the underlying channel, sigma protocol's prover and random oracle to use.
	 * @param channel
	 * @param sProver
	 * @param ro
	 */
	public ZKPOKFiatShamirFromSigmaProver(Channel channel, SigmaProverComputation sProver, RandomOracle ro) {
		
		this.sProver = sProver;
		this.ro = ro;
		this.channel = channel;
	}
	
	/**
	 * Constructor that accepts the underlying channel, sigma protocol's prover and sets default random oracle.
	 * @param channel
	 * @param sProver
	 */
	public ZKPOKFiatShamirFromSigmaProver(Channel channel, SigmaProverComputation sProver){
		
		this.sProver = sProver;
		this.ro = new HKDFBasedRO();
		this.channel = channel;
	}
	
	/**
	 * Runs the prover side of the Zero Knowledge proof.
	 * @param input must be an instance of ZKPOKFiatShamirInput that holds 
	 * 				input for the underlying sigma protocol and possible context information cont.
	 * @throws IllegalArgumentException if the given input is not an instance of ZKPOKFiatShamirProverInput.
	 * @throws IOException if failed to send the message.
	 * @throws ClassNotFoundException 
	 */
	public void prove(ZKProverInput input) throws IOException, CheatAttemptException, ClassNotFoundException {
		ZKPOKFiatShamirProof msg = generateFiatShamirProof(input);
		
		//Send (a,e,z) to V and output nothing.
		sendMsgToVerifier(msg);
		
	}

	/**
	 * Let (a,e,z) denote the prover1, verifier challenge and prover2 messages of the sigma protocol.
	 * This function computes the following calculations:
	 *
	 *		 COMPUTE the first message a in sigma, using (x,w) as input
	 *		 COMPUTE e=H(x,a,cont)
	 *		 COMPUTE the response z to (a,e) according to sigma
	 *		 RETURN (a,e,z)
	 * @param input must be an instance of ZKPOKFiatShamirInput that holds 
	 * 				input for the underlying sigma protocol and possible context information cont.
	 * @return ZKPOKFiatShamirMessage holds (a, e, z).
	 * @throws CheatAttemptException
	 * @throws IOException 
	 */
	public ZKPOKFiatShamirProof generateFiatShamirProof(ZKProverInput input) throws CheatAttemptException, IOException{
		//The given input must be an instance of ZKPOKFiatShamirProverInput that holds input for the underlying sigma protocol and possible context information cont.
		if (!(input instanceof ZKPOKFiatShamirProverInput)){
			throw new IllegalArgumentException("the given input must be an instance of ZKPOKFiatShamirProverInput");
		}
		
		//Compute the first message a in sigma, using (x,w) as input and 
		SigmaProtocolMsg a = sProver.computeFirstMsg(((ZKPOKFiatShamirProverInput) input).getSigmaInput());
		
		//Compute e=H(x,a,cont)
		byte[] e = computeChallenge((ZKPOKFiatShamirProverInput) input, a);
		
		//Compute the response z to (a,e) according to sigma
		SigmaProtocolMsg z = sProver.computeSecondMsg(e);
		
		//return (a,e,z).
		return new ZKPOKFiatShamirProof(a, e, z);
	}
	
	/**
	 * Run the following line from the protocol:
	 * "COMPUTE e=H(x,a,cont)".
	 * @param input 
	 * @param a first message of the sigma protocol.
	 * @return the computed challenge
	 * @throws IOException 
	 */
	private byte[] computeChallenge(ZKPOKFiatShamirProverInput input, SigmaProtocolMsg a) throws IOException {
		//The input to the random oracle should include the common data of the prover 
		//and verifier, and not the prover's private input.
		byte[] inputArray = convertToBytes(((SigmaProverInput) input.getSigmaInput()).getCommonParams());
		byte[] messageArray = convertToBytes(a);
		byte[] cont = input.getContext();

		byte[] inputToRO = null;
		
		if (cont != null){
			inputToRO = new byte[inputArray.length + messageArray.length + cont.length];
			System.arraycopy(cont, 0, inputToRO, inputArray.length + messageArray.length, cont.length);
		} else{
			inputToRO = new byte[inputArray.length + messageArray.length];
		}
		System.arraycopy(inputArray, 0, inputToRO, 0, inputArray.length);
		System.arraycopy(messageArray, 0, inputToRO, inputArray.length, messageArray.length);
		
		return ro.compute(inputToRO, 0, inputToRO.length, sProver.getSoundnessParam()/8);
	}
	
	/**
	 * Converts the given data to byte array using serialization mechanism.
	 * @param data to convert.
	 * @return the converted bytes.
	 * @throws IOException
	 */
	private byte[] convertToBytes(Serializable data) throws IOException{
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();  
	    ObjectOutputStream oOut  = new ObjectOutputStream(bOut);
		oOut.writeObject(data);  
		oOut.close();
		
		return bOut.toByteArray();
	}
	
	/**
	 * Sends the given message to the verifier.
	 * @param message to send to the verifier.
	 * @throws IOException if failed to send the message.
	 */
	private void sendMsgToVerifier(ZKPOKFiatShamirProof msg) throws IOException{
		try {
			//Send the message by the channel.
			channel.send(msg);
		} catch (IOException e) {
			throw new IOException("failed to send the message. The thrown exception is: " + e.getMessage());
		}	
	}

}
