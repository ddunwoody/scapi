/**
 * 
 */
package edu.biu.scapi.interactiveMidProtocols.commitmentScheme.pedersen;

import java.io.IOException;
import java.math.BigInteger;

import java.security.SecureRandom;
import java.util.Hashtable;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.OnBigIntegerCommitmentScheme;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CTReceiver;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.GroupElementSendableData;
import edu.biu.scapi.primitives.dlog.cryptopp.CryptoPpDlogZpSafePrime;
import edu.biu.scapi.primitives.dlog.miracl.MiraclDlogECF2m;
import edu.biu.scapi.securityLevel.DDH;
import edu.biu.scapi.securityLevel.PerfectlyHidingCT;

public class PedersenCTReceiver extends PedersenReceiverCore implements CTReceiver, PerfectlyHidingCT, OnBigIntegerCommitmentScheme {
	private Channel channel;
	protected DlogGroup dlog;
	private SecureRandom random;
	private BigInteger qMinusOne;
	private BigInteger a ; // Sampled random value in Zq

	private GroupElement h;  //Receiver's message
	private Map<Integer, GroupElement> commitmentMap;
	
	//private GroupElement receivedCommitment;


	public PedersenCTReceiver(Channel channel) {
		/*try {
			//Uses Miracl Koblitz 233 Elliptic curve.
			doConstruct(channel, new MiraclDlogECF2m("K-233"), new SecureRandom());
		} catch (IOException e) {
			//Why do we have this??

			//If there is a problem with the elliptic curves file, create Zp DlogGroup.
			doConstruct(channel, new CryptoPpDlogZpSafePrime(), new SecureRandom());
		}*/
		super(channel);
	}
	public PedersenCTReceiver(Channel channel, DlogGroup dlog) throws IllegalArgumentException, SecurityLevelException, InvalidDlogGroupException{
		//doConstruct(channel, dlog, new SecureRandom());
		super(channel, dlog);
	}


	/*
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
		a = sampleRandomValues();
		computeH();
		sendH();
	}

	private BigInteger sampleRandomValues() {
		BigInteger r = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		return r;
	}

	private void computeH()
	{
		h = dlog.exponentiate(dlog.getGenerator(), a);
	}

	private void sendH() throws IOException{
		CTRPedersenMessage msg = new CTRPedersenMessage(h.generateSendableData());
		try{
			channel.send(msg);
		} catch (IOException e) {
			throw new IOException("failed to send the message. The error is: " + e.getMessage());
		}	

	}


	public PedersenReceiverCommitPhaseOutput receiveCommitment() throws ClassNotFoundException, IOException {
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
		return new PedersenReceiverCommitPhaseOutput(a,msg.getId());
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
	}

*/
}