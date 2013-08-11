/**
 * 
 */
package edu.biu.scapi.interactiveMidProtocols.commitmentScheme.simpleHash;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Map;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.CommitValueException;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.BigIntegerCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.ByteArrayCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CTCDecommitmentMessage;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CTCommitter;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CommitmentPair;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.securityLevel.SecureCommit;

/**
 * <!-- begin-UML-doc --> <!-- end-UML-doc -->
 * 
 * @author user
 * @generated 
 *            "UML to Java (com.ibm.xtools.transform.uml2.java5.internal.UML2JavaTransform)"
 */
public class SimpleHashCTCommitter implements CTCommitter, SecureCommit {
	private Channel channel;
	private CryptographicHash hash;
	private int t;
	private int n;
	//private byte[] x;
	private SecureRandom random;
	private  Map<Integer, CommitmentPair> commitmentMap;
	
	
	public SimpleHashCTCommitter(Channel channel, CryptographicHash hash, int t, int n) {
		super();
		this.channel = channel;
		this.hash = hash;
		this.t = t;
		this.n = n;
		random = new SecureRandom();
		
	}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CTCommitter#preProcess()
	 */
	@Override
	public void preProcess() throws ClassNotFoundException, IOException,CheatAttemptException {
		
	}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CTCommitter#commit(edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CommitValue, int)
	 */
	@Override
	public void commit(CommitValue input, int id) throws IOException {
		//SAMPLE a random value r in {0, 1}n
		//COMPUTE c = H(r,x) (c concatenated with r)
		//SEND c to R
		if(!(input instanceof ByteArrayCommitValue))
			throw new IllegalArgumentException("The input has to be of type ByteArrayCommitValue");
		byte[] x = ((ByteArrayCommitValue)input).getX();
		byte[] r = new byte[n];
		random.nextBytes(r);
		/*
		//create an array that will hold the concatenation of r with x
		byte[] c = new byte[n+t];
		System.arraycopy(r,0, c, 0, r.length);
		System.arraycopy(input.getX(), 0, c, r.length, x.length);
		byte[] hashValArray = new byte[hash.getHashedMsgSize()];
		hash.update(c, 0, c.length);
		hash.hashFinal(hashValArray, 0);
		*/
		byte[] hashValArray = computeCommitment(x, r);
		try {
			//Send the message by the channel.
			channel.send(new CTCSimpleHashCommitmentMessage(hashValArray, id));
		} catch (IOException e) {
			throw new IOException("failed to send the message. The error is: " + e.getMessage());
		}	
		//After succeeding in sending the commitment, keep the committed value in the map together with its ID.
		commitmentMap.put(Integer.valueOf(id), new CommitmentPair(new BigInteger(r), input));
		System.out.println("x = " + x);
		System.out.println("r = " + r);
		//System.out.println("c = " + c);
		
	}
	private byte[] computeCommitment(byte[] x, byte[] r){
		//create an array that will hold the concatenation of r with x
				byte[] c = new byte[n+t];
				System.arraycopy(r,0, c, 0, r.length);
				System.arraycopy(x, 0, c, r.length, x.length);
				byte[] hashValArray = new byte[hash.getHashedMsgSize()];
				hash.update(c, 0, c.length);
				hash.hashFinal(hashValArray, 0);
				return hashValArray;
	}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CTCommitter#decommit(int)
	 */
	@Override
	public void decommit(int id) throws IOException {
		
		try{
			channel.send((CTCSimpleHashDecommitmentMessage)computeDecommit(id));
		}
		catch (IOException e) {
			throw new IOException("failed to send the message. The error is: " + e.getMessage());
		}
		//This is not according to the pseudo-code but for our programming needs. TODO Check if can be left.
		//return (CTCDecommitmentMessage) msg;
	}	

	private CTCDecommitmentMessage computeDecommit(int id){
		//fetch the commitment according to the requested ID
		CommitmentPair pair = commitmentMap.get(Integer.valueOf(id));
		byte[] x = ((ByteArrayCommitValue)pair.getX()).getX();
		return (CTCDecommitmentMessage) new CTCSimpleHashDecommitmentMessage(pair.getR().toByteArray(), x);
	}
	
	//This function is for testing purposes only. It should be deleted before publishing this part of SCAPI.
	//To be used immediately after commit function.
	public Object getCommitment(int id){
			CommitmentPair pair = commitmentMap.get(Integer.valueOf(id));
			ByteArrayCommitValue xCVal = (ByteArrayCommitValue)pair.getX();
			return computeCommitment(xCVal.getX(), pair.getR().toByteArray());
		}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CTCommitter#generateCommitValue(byte[])
	 */
	@Override
	public CommitValue generateCommitValue(byte[] x)throws CommitValueException {
		return new ByteArrayCommitValue(x);
	}

}