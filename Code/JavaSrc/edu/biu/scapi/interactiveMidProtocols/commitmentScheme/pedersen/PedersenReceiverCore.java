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
package edu.biu.scapi.interactiveMidProtocols.commitmentScheme.pedersen;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Hashtable;
import java.util.Map;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.BasicReceiverCommitPhaseOutput;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.BigIntegerCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CommitValue;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.cryptopp.CryptoPpDlogZpSafePrime;
import edu.biu.scapi.primitives.dlog.miracl.MiraclDlogECF2m;
import edu.biu.scapi.securityLevel.DDH;

/**
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */

public abstract class PedersenReceiverCore {
	protected Channel channel;
	protected DlogGroup dlog;
	private SecureRandom random;
	private BigInteger qMinusOne;
	protected BigInteger trapdoor ; // Sampled random value in Zq
									//TODO check if making this variable protected is a breach of security...

	private GroupElement h;  //Receiver's message
	private Map<Integer, GroupElement> commitmentMap;
	
	//private GroupElement receivedCommitment;


	public PedersenReceiverCore(Channel channel) throws IllegalArgumentException, SecurityLevelException, InvalidDlogGroupException{
		try {
			//Uses Miracl Koblitz 233 Elliptic curve.
			doConstruct(channel, new MiraclDlogECF2m("K-233"), new SecureRandom());
		} catch (IOException e) {
			//Why do we have this??

			//If there is a problem with the elliptic curves file, create Zp DlogGroup.
			doConstruct(channel, new CryptoPpDlogZpSafePrime(), new SecureRandom());
		}
	}
	public PedersenReceiverCore(Channel channel, DlogGroup dlog) throws IllegalArgumentException, SecurityLevelException, InvalidDlogGroupException{
		doConstruct(channel, dlog, new SecureRandom());
	}



	private void doConstruct(Channel channel, DlogGroup dlog, SecureRandom random) throws SecurityLevelException, InvalidDlogGroupException{
		//The underlying dlog group must be DDH secure.
		if (!(dlog instanceof DDH)){
			throw new SecurityLevelException("DlogGroup should have DDH security level");
		}
		if(!dlog.validateGroup())
			throw new InvalidDlogGroupException();

		this.channel = channel;
		this.dlog = dlog;
		this.random = random;
		qMinusOne =  dlog.getOrder().subtract(BigInteger.ONE);
		commitmentMap = new Hashtable<Integer, GroupElement>();
	}



	public void preProcess() throws IOException {
		trapdoor = sampleRandomValues();
		computeH();
		sendH();
	}

	private BigInteger sampleRandomValues() {
		BigInteger r = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		return r;
	}

	private void computeH()
	{
		h = dlog.exponentiate(dlog.getGenerator(), trapdoor);
	}

	private void sendH() throws IOException{
		CTRPedersenMessage msg = new CTRPedersenMessage(h.generateSendableData());
		try{
			channel.send(msg);
		} catch (IOException e) {
			throw new IOException("failed to send the message. The error is: " + e.getMessage());
		}	

	}


	public BasicReceiverCommitPhaseOutput receiveCommitment() throws ClassNotFoundException, IOException {
		CTCPedersenCommitmentMessage msg = null;
		try{
			msg = (CTCPedersenCommitmentMessage) channel.receive();
		} catch (ClassNotFoundException e) {
			throw new ClassNotFoundException("Failed to receive commitment. The error is: " + e.getMessage());
		} catch (IOException e) {
			throw new IOException("Failed to receive commitment. The error is: " + e.getMessage());
		}

		GroupElement receivedCommitment = dlog.reconstructElement(true,msg.getC());
		commitmentMap.put(Integer.valueOf(msg.getId()), receivedCommitment);
		return new BasicReceiverCommitPhaseOutput(msg.getId());
	}

	public CommitValue receiveDecommitment(int id) throws ClassNotFoundException, IOException {
		CTCPedersenDecommitmentMessage msg = null;
		try {
			msg = (CTCPedersenDecommitmentMessage) channel.receive();

		} catch (ClassNotFoundException e) {
			throw new ClassNotFoundException("Failed to receive decommitment. The error is: " + e.getMessage());
		} catch (IOException e) {
			throw new IOException("Failed to receive decommitment. The error is: " + e.getMessage());
		}
		
		
/*
		//Calculate cc = g^r * h^x
		GroupElement gTor = dlog.exponentiate(dlog.getGenerator(),msg.getR());
		GroupElement hTox = dlog.exponentiate(h,msg.getX());
		//Fetch received commitment according to ID
		GroupElement receivedCommitment = commitmentMap.get(Integer.valueOf(id));
		if (receivedCommitment.equals(dlog.multiplyGroupElements(gTor, hTox)))
			return new BigIntegerCommitValue(msg.getX());
		//In the pseudocode it says to return X and ACCEPT if valid commitment else, REJECT.
		//For now we return null as a mode of reject. If the returned value of this function is not null then it means ACCEPT
		return null;
*/		
		return processDecommitment(id, msg.getX(), msg.getR());
	}
	
	protected CommitValue processDecommitment(int id, BigInteger x, BigInteger r) {
		//Calculate cc = g^r * h^x
		GroupElement gTor = dlog.exponentiate(dlog.getGenerator(),r);
		GroupElement hTox = dlog.exponentiate(h,x);
		//Fetch received commitment according to ID
		GroupElement receivedCommitment = commitmentMap.get(Integer.valueOf(id));
		if (receivedCommitment.equals(dlog.multiplyGroupElements(gTor, hTox)))
			return new BigIntegerCommitValue(x);
		//In the pseudocode it says to return X and ACCEPT if valid commitment else, REJECT.
		//For now we return null as a mode of reject. If the returned value of this function is not null then it means ACCEPT
		return null;
	}
}
