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
import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Hashtable;
import java.util.Map;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.BasicReceiverCommitPhaseOutput;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.BigIntegerCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CTCDecommitmentMessage;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CommitmentPair;
//import edu.biu.scapi.interactiveMidProtocols.ot.semiHonest.OTRSemiHonestMessage;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.cryptopp.CryptoPpDlogZpSafePrime;
import edu.biu.scapi.primitives.dlog.miracl.MiraclDlogECF2m;
import edu.biu.scapi.securityLevel.DDH;
import edu.biu.scapi.securityLevel.PerfectlyHidingCT;
/**
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public abstract class PedersenCommitterCore {
	/*
	public class CommitmentPair{
		BigInteger x;	//The commitment
		BigInteger r;	//The random value used to commit
		
		CommitmentPair(BigInteger x, BigInteger r){
			this.x  =x;
			this.r = r;
		}
		public BigInteger getX(){
			return x;
		}
		public BigInteger getR(){
			return r;
		}
	}
	*/
	protected Channel channel;
	protected DlogGroup dlog;
	private SecureRandom random;
	private BigInteger qMinusOne;
	protected Map<Integer, CommitmentPair> commitmentMap;			//The key to the map is an ID and the value is a pair that has the Committer's private input x in Zq and the random value
																//used to commit x.
										//Each committed value is sent together with an ID so that the receiver can keep it it in some data structure. This is necessary
										//in the cases that the same instances of committer and receiver can be used for performing various commitments utilizing the values calculated
										//during the pre-process stage for the sake of efficiency.
	
	//private BigInteger x; 			//Committer's private input x in Zq
	//private BigInteger r; 			//Random value sampled during the sampleRandomValues stage;
	//private CTRPedersenMessage msg; //Message obtained from the receiver during the preProcess stage. Later is needed to commit.
    private GroupElement h; 		//The content of the message obtained from the receiver. 	
	//private int id;					
	public PedersenCommitterCore(Channel channel) throws IllegalArgumentException, SecurityLevelException, InvalidDlogGroupException{
		try {
			//Uses Miracl Koblitz 233 Elliptic curve.
			doConstruct(channel, new MiraclDlogECF2m("K-233"), new SecureRandom());
		} catch (IOException e) {
			//Why do we have this??
			
			//If there is a problem with the elliptic curves file, create Zp DlogGroup.
			doConstruct(channel, new CryptoPpDlogZpSafePrime(), new SecureRandom());
		}
	}
	
	public PedersenCommitterCore(Channel channel, DlogGroup dlog) throws IllegalArgumentException, SecurityLevelException, InvalidDlogGroupException{
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
		commitmentMap = new Hashtable<Integer, CommitmentPair>();
	}
	

	public void preProcess() throws ClassNotFoundException, IOException, CheatAttemptException {
	
		CTRPedersenMessage msg = waitForMessageFromReceiver();
		//If the element cannot be reconstructed IllegalArgumentException gets thrown....It is weird for a function that doesn't have any arguments...
		h = dlog.reconstructElement(true, msg.getH());
		if(!dlog.isMember(h))
				throw new CheatAttemptException("h element is not a member of the current DlogGroup");
		System.out.println("h = " + h);
	
	}

	
	public void  commit(CommitValue in, int id) throws IOException, IllegalArgumentException {
		
		if (!(in instanceof BigIntegerCommitValue))
			throw new IllegalArgumentException("The input must be of type BigIntegerCommitValue");
		BigInteger r = sampleRandomValues();	
		BigInteger x = ((BigIntegerCommitValue)in).getX();
		GroupElement c =  computeCommitment(x, r);
		try {
			//Send the message by the channel.
			channel.send(new CTCPedersenCommitmentMessage(c.generateSendableData(), id));
		} catch (IOException e) {
			throw new IOException("failed to send the message. The error is: " + e.getMessage());
		}	
		//After succeeding in sending the commitment, keep the committed value in the map together with its ID.
		commitmentMap.put(Integer.valueOf(id), new CommitmentPair(r, new BigIntegerCommitValue(x)));
		System.out.println("x = " + x);
		System.out.println("r = " + r);
		System.out.println("c = " + c);
		//This is not according to the pseudo-code but for our programming needs. TODO Check if can be left.
		//return c;
	}

	//This function is for testing purposes only. It should be deleted before publishing this part of SCAPI.
	//To be used immediately after commit function.
	public Object getCommitment(int id){
		CommitmentPair pair = commitmentMap.get(Integer.valueOf(id));
		BigIntegerCommitValue xCVal = (BigIntegerCommitValue)pair.getX();
		return computeCommitment(xCVal.getX(), pair.getR());
	}
	
	public void decommit(int id) throws IOException {
		
		try{
			channel.send((CTCPedersenDecommitmentMessage)computeDecommit(id));
		}
		catch (IOException e) {
			throw new IOException("failed to send the message. The error is: " + e.getMessage());
		}
		//This is not according to the pseudo-code but for our programming needs. TODO Check if can be left.
		//return (CTCDecommitmentMessage) msg;
	}	
	
	CTCDecommitmentMessage computeDecommit(int id){
		//fetch the commitment according to the requested ID
		CommitmentPair pair = commitmentMap.get(Integer.valueOf(id));
		BigIntegerCommitValue xCVal = (BigIntegerCommitValue)pair.getX();
		return (CTCDecommitmentMessage) new CTCPedersenDecommitmentMessage(xCVal.getX(),pair.getR());
	}

	
	private BigInteger sampleRandomValues() {
		BigInteger r = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		return r;
	}
	
	private CTRPedersenMessage waitForMessageFromReceiver() throws ClassNotFoundException, IOException{
		Serializable message = null;
		try {
			message = channel.receive();
		} catch (ClassNotFoundException e) {
			throw new ClassNotFoundException("Failed to receive message. The error is: " + e.getMessage());
		} catch (IOException e) {
			throw new IOException("Failed to receive message. The error is: " + e.getMessage());
		}
		if (!(message instanceof CTRPedersenMessage)){
			throw new IllegalArgumentException("The received message should be an instance of OTSMessage");
		}
		return (CTRPedersenMessage) message;
	}
	
	
	private GroupElement computeCommitment(BigInteger x, BigInteger r) {		
		GroupElement c = dlog.multiplyGroupElements(dlog.exponentiate(dlog.getGenerator(), r), dlog.exponentiate(h, x));
		return c;
	}

}

