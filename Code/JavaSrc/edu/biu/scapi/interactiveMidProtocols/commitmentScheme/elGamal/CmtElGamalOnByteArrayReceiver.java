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
package edu.biu.scapi.interactiveMidProtocols.commitmentScheme.elGamal;

import java.io.IOException;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.generals.ScapiDefaultConfiguration;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtByteArrayCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCCommitmentMsg;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCDecommitmentMessage;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtReceiver;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtOnByteArray;
import edu.biu.scapi.midLayer.asymmetricCrypto.encryption.ScElGamalOnByteArray;
import edu.biu.scapi.midLayer.ciphertext.ElGamalOnByteArrayCiphertext.ElGamalOnByteArraySendableData;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.kdf.HKDF;
import edu.biu.scapi.primitives.kdf.KeyDerivationFunction;
import edu.biu.scapi.primitives.prf.bc.BcHMAC;
import edu.biu.scapi.securityLevel.PerfectlyBindingCmt;
import edu.biu.scapi.tools.Factories.DlogGroupFactory;

/**
 * This class implements the receiver side of the ElGamal commitment. <p>
 * It uses El Gamal encryption for byte arrays, that is, the encryption class used is 
 * ScElGamalOnByteArray. This default cannot be changed.<p>
 *
 * The pseudo code of this protocol can be found in Protocol 3.4 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class CmtElGamalOnByteArrayReceiver extends CmtElGamalReceiverCore implements CmtReceiver, PerfectlyBindingCmt, CmtOnByteArray {

	KeyDerivationFunction kdf;
	
	/**
	 * This constructor lets the caller pass the channel, the dlog group and the 
	 * KeyDerivation function to work with. 
	 * The El Gamal option (ScElGamalOnByteArray)is set by default by the constructor 
	 * and cannot be changed.
	 * @param channel used for the communication
	 * @param dlog	Dlog group
	 * @param kdf key derivation function
	 * @throws CheatAttemptException if the receiver suspects the committer trying to cheat.
	 * @throws ClassNotFoundException if there was a problem during serialization.
	 * @throws SecurityLevelException if the given dlog is not DDH - secure
	 * @throws InvalidDlogGroupException if the given dlog is not valid
	 * @throws IOException if there was a problem during communication
	 */
	public CmtElGamalOnByteArrayReceiver(Channel channel, DlogGroup dlog, KeyDerivationFunction kdf) throws IllegalArgumentException, SecurityLevelException, InvalidDlogGroupException, ClassNotFoundException, IOException, CheatAttemptException {
		super(channel, dlog, new ScElGamalOnByteArray(dlog, kdf));
		this.kdf = kdf;
	}
	
	/**
	 * This constructor uses default Dlog group and El Gamal.
	 * @param channel
	 * @throws CheatAttemptException if the receiver suspects the committer trying to cheat.
	 * @throws IOException if there was a problem during communication
	 * @throws ClassNotFoundException if there was a problem during serialization.
	 */
	public CmtElGamalOnByteArrayReceiver(Channel channel) throws ClassNotFoundException, IOException, CheatAttemptException {
		String dlogGroupName = ScapiDefaultConfiguration.getInstance().getProperty("DDHDlogGroup");
		DlogGroup dlog =  null;
		kdf = new HKDF(new BcHMAC());
		//Create the dlog group 
		try {
			dlog = DlogGroupFactory.getInstance().getObject(dlogGroupName);
		} catch (FactoriesException e1) {
			e1.printStackTrace();
		}
		//Proceed with construction of ElGamalCTRCore instance
		try {
			doConstruct(channel, dlog , new ScElGamalOnByteArray(dlog, kdf));
		} catch (SecurityLevelException e) {
			e.printStackTrace();
		} catch (InvalidDlogGroupException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Proccesses the decommitment phase.<p>
	 * "IF NOT<p>
	 *	•	u=g^r <p>
	 *	•	v = h^r * x<p>
	 *	•	x in G<p>
	 *		OUTPUT REJ<p>
	 *	ELSE<p>
	 *	    OUTPUT ACC and value x"<p>
	 * @param id the id of the commitment.
	 * @param msg the receiver message from the committer
	 * @return the committed value if the decommit succeeded; null, otherwise.
	 */
	public CmtCommitValue verifyDecommitment(CmtCCommitmentMsg commitmentMsg, CmtCDecommitmentMessage decommitmentMsg) {
		if (!(decommitmentMsg instanceof CmtElGamalDecommitmentMessage)){
			throw new IllegalArgumentException("decommitmentMsg should be an instance of CmtElGamalDecommitmentMessage");
		}
		if (!(commitmentMsg instanceof CmtElGamalCommitmentMessage)){
			throw new IllegalArgumentException("commitmentMsg should be an instance of CmtElGamalCommitmentMessage");
		}
		
		byte[] x = null;
		if (!(decommitmentMsg.getX() instanceof byte[]))
			throw new IllegalArgumentException("x value is not an instance of byte[]");
		
		try{
			x = (byte[]) decommitmentMsg.getX();
		}catch (IllegalArgumentException e){
			throw new IllegalArgumentException("Failed to receive decommitment. The error is: " + e.getMessage());
		}

		int len = x.length;
		
		//Fetch received commitment according to ID
		if (!(commitmentMsg.getCommitment() instanceof ElGamalOnByteArraySendableData))
			throw new IllegalArgumentException("commitment value is not an instance of ElGamalOnByteArraySendableData");

		GroupElement u = dlog.reconstructElement(true,((ElGamalOnByteArraySendableData) commitmentMsg.getCommitment()).getCipher1());
		byte[] v = ((ElGamalOnByteArraySendableData)commitmentMsg.getCommitment()).getCipher2();
		if (len != v.length){
			return null;
		}
		
		GroupElement gToR = dlog.exponentiate(dlog.getGenerator(), ((CmtElGamalDecommitmentMessage) decommitmentMsg).getR().getR());	
		GroupElement hToR = dlog.exponentiate(publicKey.getH(), ((CmtElGamalDecommitmentMessage) decommitmentMsg).getR().getR());
		
		byte[] hToRBytes = dlog.mapAnyGroupElementToByteArray(hToR);
		byte[] c2 = kdf.deriveKey(hToRBytes, 0, hToRBytes.length, x.length).getEncoded();
		
		//Xores the result from the kdf with the plaintext.
		for(int i=0; i<x.length; i++){
			c2[i] = (byte) (c2[i] ^ x[i]);
		}
		
		boolean valid = u.equals(gToR);

		for (int i=0; i<x.length; i++){
			valid = valid && (v[i] == c2[i]);
		}
		
		if(valid)
			return new CmtByteArrayCommitValue(x);
		return null;
	}
	
	/**
	 * This function converts the given commit value to a byte array. 
	 * @param value
	 * @return the generated bytes.
	 */
	public byte[] generateBytesFromCommitValue(CmtCommitValue value){
		if (!(value instanceof CmtByteArrayCommitValue))
			throw new IllegalArgumentException("The given value must be of type CmtByteArrayCommitValue");
		return (byte[]) value.getX();
	}
	

}
