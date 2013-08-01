/**
 * 
 */
package edu.biu.scapi.interactiveMidProtocols.committmentScheme.elGamalHash;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Hashtable;
import java.util.Map;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.CommitValueException;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.committmentScheme.ByteArrayCommitValue;
import edu.biu.scapi.interactiveMidProtocols.committmentScheme.CTCommitter;
import edu.biu.scapi.interactiveMidProtocols.committmentScheme.CommitValue;
import edu.biu.scapi.interactiveMidProtocols.committmentScheme.elGamal.CTCElGamalDecommitmentMessage;
import edu.biu.scapi.interactiveMidProtocols.committmentScheme.elGamal.ElGamalCTCCore;
import edu.biu.scapi.midLayer.asymmetricCrypto.encryption.ScElGamalOnByteArray;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.primitives.hash.bc.BcSHA224;
import edu.biu.scapi.primitives.kdf.HKDF;
import edu.biu.scapi.primitives.prf.bc.BcHMAC;
import edu.biu.scapi.securityLevel.SecureCommit;

/**
 * <!-- begin-UML-doc --> <!-- end-UML-doc -->
 * 
 * @author user
 * @generated 
 *            "UML to Java (com.ibm.xtools.transform.uml2.java5.internal.UML2JavaTransform)"
 */
public class ElGamalHashCTCommitter extends ElGamalCTCCore implements CTCommitter, SecureCommit {

	private CryptographicHash hash;
	private Map<Integer, byte[]> hashCommitmentMap;

	/*
	 *Too complicated to have a default constructor. MAnhy things need to be suitable to each other. Cannot have some being default (and unknown to the caller) and some defined by the caller.
	public ElGamalHashCTCommitter(Channel channel) throws IllegalArgumentException, SecurityLevelException, InvalidDlogGroupException{
		super(channel, new );
		hash = new BcSHA224(); 		//This default hash suits the default DlogGroup of the underlying Committer.
		hashCommitmentMap = new Hashtable<Integer, byte[]>();
	}
	*/

	public ElGamalHashCTCommitter(Channel channel, DlogGroup dlog, CryptographicHash hash) throws IllegalArgumentException, SecurityLevelException, InvalidDlogGroupException{
		super(channel, dlog, new ScElGamalOnByteArray(dlog, new HKDF(new BcHMAC())));
		if (hash.getHashedMsgSize()> (dlog.getOrder().bitLength()/8)){
			throw new IllegalArgumentException("The size in bytes of the resulting hash is bigger than the size in bytes of the order of the DlogGroup.");
		}
		this.hash = hash;
		hashCommitmentMap = new Hashtable<Integer, byte[]>();
	}


	/* (non-Javadoc)
	 * @see edu.biu.scapi.interactiveMidProtocols.committmentScheme.CTCommitter#commit(edu.biu.scapi.interactiveMidProtocols.committmentScheme.CommitValue, int)
	 */
	@Override
	public void commit(CommitValue input, int id) throws IOException {
		//Check that the input x is in the end a byte[]
		if (!(input instanceof ByteArrayCommitValue))
			throw new IllegalArgumentException("The input must be of type ByteArrayCommitValue");
		//Hash the input x with the hash function
		byte[] x  = ((ByteArrayCommitValue)input).getX();
		//Keep the original commit value x and its id in the commitmentMap, needed for later (during the decommit phase).
		hashCommitmentMap.put(Integer.valueOf(id), x);

		//calculate H(x) = Hash(x)
		byte[] hashValArray = new byte[hash.getHashedMsgSize()];
		hash.update(x, 0, x.length);
		hash.hashFinal(hashValArray, 0);
		//If it is possible to encode the obtained byte[] to a group element in the group, do it and then
		//proceed to commit using the regular El Gamal Committer.
		int k = dlog.getMaxLengthOfByteArrayForEncoding();
		System.out.println("k = " + k + ", hashValArray.length = " + hashValArray.length);
		/*GroupElement el = dlog.encodeByteArrayToGroupElement(hashValArray); 
		if(el != null)
			super.commit(new GroupElementCommitValue(el), id);
		else
			System.out.println("Cannot commit this value, is not a legal element in the group");
		*/
		super.commit(new ByteArrayCommitValue(hashValArray), id);
	}



	public void decommit(int id) throws IOException {
		//Fetch the commitment according to the requested ID
		byte[] x = hashCommitmentMap.get(Integer.valueOf(id));
		//Get the relevant random value used in the commitment phase
		//CTCPedersenDecommitmentMessage underMsg = (CTCPedersenDecommitmentMessage) computeDecommit(id);
		BigInteger r = (commitmentMap.get(id)).getR();
		//Is it OK to convert the byte[] x to BigInteger?
		//CTCElGamalHashDecommitmentMessage msg = new CTCElGamalHashDecommitmentMessage(x,r);
		CTCElGamalDecommitmentMessage msg = new CTCElGamalDecommitmentMessage(x,r);
		try{
			channel.send(msg);
		}
		catch (IOException e) {
			throw new IOException("failed to send the message. The error is: " + e.getMessage());
		}
	}


	/* (non-Javadoc)
	 * @see edu.biu.scapi.interactiveMidProtocols.committmentScheme.CTCommitter#getCommitment(int)
	 */
	@Override
	public Object getCommitment(int id) {
		// TODO Auto-generated method stub
		return null;
	}


	/* (non-Javadoc)
	 * @see edu.biu.scapi.interactiveMidProtocols.committmentScheme.CTCommitter#generateCommitValue(byte[])
	 */
	@Override
	public CommitValue generateCommitValue(byte[] x)throws CommitValueException {
		return new ByteArrayCommitValue(x);
	}

}