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


/**
 * 
 */
package edu.biu.scapi.midLayer.asymmetricCrypto.keys;

import java.math.BigInteger;
import java.util.Vector;

import edu.biu.scapi.primitives.trapdoorPermutation.RSAModulus;
import edu.biu.scapi.tools.math.MathAlgorithms;

/**
 * This class represents a Private Key suitable for the Damgard-Jurik Encryption Scheme. Although the constructor is  public, it should only be instantiated by the 
 * Encryption Scheme itself via the generateKey function. 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class ScDamgardJurikPrivateKey implements DamgardJurikPrivateKey, KeySendableData {

	private static final long serialVersionUID = 4536731164134226986L;
	
	BigInteger t;
	BigInteger dForS1; //Pre-calculated d in the case the s == 1
	private BigInteger p;
	private BigInteger q;
	
	public ScDamgardJurikPrivateKey(RSAModulus rsaMod){
		
		this.p = rsaMod.p;
		this.q = rsaMod.q;
		
		//Computes t = lcm(p-1, q-1) where lcm is the least common multiple and can be computed as lcm(a,b) = a*b/gcd(a,b).
		BigInteger pMinus1 = rsaMod.p.subtract(BigInteger.ONE);
		BigInteger qMinus1 = rsaMod.q.subtract(BigInteger.ONE);
		BigInteger gcdPMinus1QMinus1 = pMinus1.gcd(qMinus1);
		t = (pMinus1.multiply(qMinus1)).divide(gcdPMinus1QMinus1);
		
		//Precalculate d for the case that s == 1
		dForS1 = generateD(rsaMod.n, t); 
	}
	
	/**
	 * This function generates a value d such that d = 1 mod N and d = 0 mod t, using the Chinese Remainder Theorem.
	 */
	private BigInteger generateD(BigInteger N, BigInteger t){
		Vector<BigInteger> congruences = new Vector<BigInteger>();
		congruences.add(BigInteger.ONE);
		congruences.add(BigInteger.ZERO);
		Vector<BigInteger> moduli = new Vector<BigInteger>();
		moduli.add(N);
		moduli.add(t);
		BigInteger d = MathAlgorithms.chineseRemainderTheorem(congruences, moduli);
		return d;
	}
	
	/* (non-Javadoc)
	 * @see java.security.Key#getAlgorithm()
	 */
	@Override
	public String getAlgorithm() {
		return "DamgardJurik";
	}

	/* (non-Javadoc)
	 * @see java.security.Key#getFormat()
	 */
	@Override
	public String getFormat() {
		// TODO Auto-generated method stub
		return null;
	}

	/* (non-Javadoc)
	 * @see java.security.Key#getEncoded()
	 */
	@Override
	public byte[] getEncoded() {
		// TODO Auto-generated method stub
		return null;
	}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.keys.DamgardJurikPrivateKey#getT()
	 */
	@Override
	public BigInteger getT() {
		return t;
	}
	
	public BigInteger getDForS1(){
		return dForS1;
	}
	
	public BigInteger getP(){
		return p;
	}
	
	public BigInteger getQ(){
		return q;
	}

	/** 
	 * This function is used when an Damgard Jurik Private Key needs to be sent via a {@link edu.biu.scapi.comm.Channel} or any other means of sending data (including serialization).
	 * It retrieves all the data needed to reconstruct this Private Key at a later time and/or in a different VM.
	 * It puts all the data in an instance of the relevant class that implements the KeySendableData interface.
	 * In order to deserialize this into a DamgardJurikPrivateKey all you need to do is cast the serialized object with (DamgardJurikPrivateKey)
	 */
	@Override
	public KeySendableData generateSendableData() {
		//Since ScDamgardJurikPrivateKey is both a PrivateKey and a KeySendableData, on the one hand it has to implement
		//the generateSendableData() function, but on the other hand it is in itself an KeySendableData, so we do not really
		//generate sendable data, but just return this object.
		return this;
	}
}
