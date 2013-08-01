/**
 * %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 * 
Copyright (c) 2012 - SCAPI (http://crypto.biu.ac.il/scapi)
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
package edu.biu.scapi.interactiveMidProtocols.committmentScheme.elGamal;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.committmentScheme.CTReceiver;
import edu.biu.scapi.interactiveMidProtocols.committmentScheme.CommitValue;
import edu.biu.scapi.interactiveMidProtocols.committmentScheme.GroupElementCommitValue;
import edu.biu.scapi.midLayer.asymmetricCrypto.encryption.ScElGamalOnGroupElement;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScElGamalPublicKey;
import edu.biu.scapi.midLayer.ciphertext.ElGamalOnGroupElementCiphertext.ElGamalOnGrElSendableData;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.GroupElementSendableData;
import edu.biu.scapi.securityLevel.PerfectlyBindingCT;

/**
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class ElGamalCTReceiver extends ElGamalCTRCore implements CTReceiver, PerfectlyBindingCT {

	/**
	 * @param channel
	 * @throws IllegalArgumentException
	 * @throws SecurityLevelException
	 * @throws InvalidDlogGroupException
	 */
	/*
	public ElGamalCTReceiver(Channel channel) throws IllegalArgumentException, SecurityLevelException, InvalidDlogGroupException {
		super(channel);
	}
	 */
	public ElGamalCTReceiver(Channel channel, DlogGroup dlog) throws IllegalArgumentException, SecurityLevelException, InvalidDlogGroupException {
		super(channel, dlog, new ScElGamalOnGroupElement(dlog));	
	}
	
	/* (non-Javadoc)
	 * @see edu.biu.scapi.interactiveMidProtocols.committmentScheme.ElGamalCTRCore#processDecommitment(int, edu.biu.scapi.interactiveMidProtocols.committmentScheme.CTCElGamalDecommitmentMessage)
	 */
	@Override
	protected CommitValue processDecommitment(int id, CTCElGamalDecommitmentMessage msg) {
		GroupElement xEl = null;

		try{
			xEl = dlog.reconstructElement(true, (GroupElementSendableData) msg.getX());
		}catch (IllegalArgumentException e){
			throw new IllegalArgumentException("Failed to receive decommitment. The error is: " + e.getMessage());
		}

		//First check if x is a group element in the current Dlog Group, if not return null meaning rejection:
		if(!dlog.isMember(xEl))
			return null;

		//Fetch received commitment according to ID
		CTCElGamalCommitmentMessage receivedCommitment = commitmentMap.get(Integer.valueOf(id));

		GroupElement h = ((ScElGamalPublicKey)elGamal.reconstructPublicKey(receivedCommitment.getPublicKey())).getH();
		if(!dlog.isMember(h))
			return null;

		GroupElement u = dlog.reconstructElement(true,((ElGamalOnGrElSendableData)receivedCommitment.getCipherData()).getCipher1());
		GroupElement v = dlog.reconstructElement(true,((ElGamalOnGrElSendableData)receivedCommitment.getCipherData()).getCipher2());
		GroupElement gToR = dlog.exponentiate(dlog.getGenerator(), msg.getR());	
		GroupElement hToR = dlog.exponentiate(h, msg.getR());
		System.out.println("u = " + u.toString());
		System.out.println("v = " + v.toString());
		System.out.println("gToR = " + gToR.toString());
		System.out.println("hToR = " + hToR.toString());
		System.out.println("hTor * x = " + dlog.multiplyGroupElements(hToR, xEl));

		if( u.equals(gToR) && v.equals(dlog.multiplyGroupElements(hToR, xEl)) )
			return new GroupElementCommitValue(xEl);
		return null;
	}
}