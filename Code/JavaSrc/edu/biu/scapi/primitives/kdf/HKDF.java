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


package edu.biu.scapi.primitives.kdf;

import java.security.InvalidKeyException;
import java.util.logging.Level;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.encoders.Hex;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.generals.Logging;
import edu.biu.scapi.primitives.prf.Hmac;
import edu.biu.scapi.tools.Factories.PrfFactory;


/** 
 * Concrete class of key derivation function for HKDF.
 * This is a key derivation function that has a rigorous justification as to its security.
 * 
  * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public final class HKDF implements KeyDerivationFunction {
	
	private Hmac hmac; // the underlying hmac
	
	/**
	 * Constructor that accepts a name of Hmac and creates the HKDF object with it.
	 * @param hmac the underlying object
	 * @throws FactoriesException if this object is not initialized
	 */
	public HKDF(String hmac) throws FactoriesException{
		//creates the underlying hmac via the prf factory, and calls the constructor that gets an object of type Hmac to continue to setting the key.
		this((Hmac) PrfFactory.getInstance().getObject(hmac));
	}
	
	/**
	 * Constructor that accepts an HMAC to be the underlying object.
	 * @param hmac the underlying hmac. 
	 */
	public HKDF(Hmac hmac) {
		
		this.hmac = hmac;
		
	}

	/**
	 * Does round 2 to t of HKDF algorithm. The pseudo code:
	 * FOR i = 2 TO t
	 * K(i) = HMAC(PRK,(K(i-1),CTXinfo,i)) [key=PRK, data=(K(i-1),CTXinfo,i)]
	 * @param outLen the required output key length
	 * @param iv the iv : ctxInfo
	 * @param hmacLength the size of the output of the hmac.
	 * @param outBytes the result of the overall computation
	 * @param intermediateOutBytes round result K(i) in the pseudocode
	 */
	private void nextRounds(int outLen, byte[] iv, int hmacLength,
			byte[] outBytes, byte[] intermediateOutBytes) {
		
		int rounds = (int) Math.ceil((float)outLen/(float)hmacLength); //the smallest number so that  hmacLength * rounds >= outLen
		
		int currentInBytesSize;	//the size of the CTXInfo and also the round;
		
		if(iv!=null)
			currentInBytesSize = hmacLength + iv.length + 1;//the size of the CTXInfo and also the round;
		else//no CTXInfo
			currentInBytesSize = hmacLength + 1;//the size without the CTXInfo and also the round;
		
		//the result of the current computation
		byte[] currentInBytes = new byte[currentInBytesSize];
		
		
		Integer roundIndex;
		//for rounds 2 to t 
		if(iv!=null)
			//in case we have an iv. puts it (ctxInfo after the K from the previous round at position hmacLength).
			System.arraycopy(iv, 0, currentInBytes, hmacLength , iv.length);
				
		for(int i=2;i<=rounds; i++){
			
			roundIndex = new Integer(i); //creates the round integer for the data
			
			//copies the output of the last results
			System.arraycopy(intermediateOutBytes, 0, currentInBytes, 0, hmacLength);
				
			//copies the round integer to the data array
			currentInBytes[currentInBytesSize - 1] = roundIndex.byteValue();
			
			
			//operates the hmac to get the round output 
			try {
				hmac.computeBlock(currentInBytes, 0, currentInBytes.length, intermediateOutBytes, 0);
			} catch (IllegalBlockSizeException e) {
				// souldn't happen since the offsets and length are within the arrays
				Logging.getLogger().log(Level.WARNING, e.toString());
			}
			
			if(i==rounds){//We fill the rest of the array with a portion of the last result.
				
				//copies the results to the output array
				System.arraycopy(intermediateOutBytes, 0,outBytes , hmacLength*(i-1), outLen - hmacLength*(i-1));
			}
			else{
				//copies the results to the output array
				System.arraycopy(intermediateOutBytes, 0,outBytes , hmacLength*(i-1), hmacLength);
			}				
		}
	}

	/**
	 * First round of HKDF algorithm. The pseudo code: 
	 * K(1) = HMAC(PRK,(CTXinfo,1)) [key=PRK, data=(CTXinfo,1)]
	 * @param iv ctxInfo
	 * @param intermediateOutBytes round result K(1) in the pseudocode
	 * @param hmacLength the size of the output of the hmac.
	 * @param outBytes the result of the overall computation
	 */
	private void firstRound(byte [] outBytes, byte[] iv, byte[] intermediateOutBytes, int outLength)  {
		Integer one;
		//round 1
		byte[] firstRoundInput;//data for the creating K(1)
		if(iv!=null)
			firstRoundInput = new  byte[iv.length + 1];
		else
			firstRoundInput = new  byte[1];
		
		//copies the CTXInfo - iv
		if(iv!=null)
			System.arraycopy(iv, 0, firstRoundInput,0 , iv.length);
		
		one = new Integer(1);//creates the round integer for the data
			
		//copies the integer with zero to the data array
		firstRoundInput[firstRoundInput.length - 1] = one.byteValue();
		
			
		//first computes the new key. The new key is the result of computing the hmac function.
		try {
			//calculate K(1) and put it in intermediateOutBytes.
			hmac.computeBlock(firstRoundInput, 0, firstRoundInput.length, intermediateOutBytes, 0);
		} catch (IllegalBlockSizeException e) {	
			// souldn't happen since the offsets and length are within the arrays
			Logging.getLogger().log(Level.WARNING, e.toString());
		} 
		
		//copies the results to the output array
		System.arraycopy(intermediateOutBytes, 0,outBytes , 0, outLength);
	}


	public SecretKey deriveKey(byte[] entropySource, int inOff, int inLen, int outLen) {
		//there is no auxiliary information, sends an empty iv.
		return deriveKey(entropySource, inOff, inLen, outLen, null);
		
	}

	
	/**
	 * This function derives a new key from the source key material key.
	 * The pseudo-code of this function is as follows:
	 * 
	 *   COMPUTE PRK = HMAC(XTS, SKM) [key=XTS, data=SKM]
	 *   Let t be the smallest number so that t * |H|>L where |H| is the HMAC output length
	 *   K(1) = HMAC(PRK,(CTXinfo,1)) [key=PRK, data=(CTXinfo,1)]
	 *   FOR i = 2 TO t
	 *     K(i) = HMAC(PRK,(K(i-1),CTXinfo,i)) [key=PRK, data=(K(i-1),CTXinfo,i)]
	 *   OUTPUT the first L bits of K(1),…,K(t)
	 *   
	 *   @param iv - CTXInfo 
	 * 
	 */
	public SecretKey deriveKey(byte[] entropySource, int inOff, int inLen, int outLen, byte[] iv) {
		
		//checks that the offset and length are correct
		if ((inOff > entropySource.length) || (inOff+inLen > entropySource.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given input buffer");
		}
		
		//Sets the hmac object with a fixed key that was randomly generated once. This is done every time a new derived key is requested otherwise the result of deriving
		//a key from the same entropy source will be different in subsequent calls to this function (as long as the same instance of HKDF is used). 
		try {
			hmac.setKey(new SecretKeySpec(Hex.decode("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"), ""));
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		int hmacLength = hmac.getBlockSize();                           //the size of the output of the hmac.
		byte[] outBytes = new byte[outLen];                             //the output key
		byte[] roundKey = new byte[hmacLength];							//PRK from the pseudocode
		byte[] intermediateOutBytes = new byte[hmacLength];             //round result K(i) in the pseudocode
		
		
		//first computes the new key. The new key is the result of computing the hmac function.
		try {
			//roundKey is now K(0)
			hmac.computeBlock(entropySource, 0, entropySource.length, roundKey, 0);
		} catch (IllegalBlockSizeException e) {//should not happen since the roundKey is of the right size.
			
			Logging.getLogger().log(Level.WARNING, e.toString());
		}
		
		
		//init the hmac with the new key. From now on this is the key for all the rounds.
		try {
			hmac.setKey(new SecretKeySpec(roundKey, "HKDF"));
		} catch (InvalidKeyException e) {
			//shoudln't happen since the key is the output of compute block and its length is ok
			Logging.getLogger().log(Level.WARNING, e.toString());
		}
		
		//calculates the first round
		//K(1) = HMAC(PRK,(CTXinfo,1)) [key=PRK, data=(CTXinfo,1)]
		if (outLen < hmacLength){
			firstRound(outBytes, iv, intermediateOutBytes, outLen);
		} else {
			firstRound(outBytes, iv, intermediateOutBytes, hmacLength);
		}
		
		//calculates the next rounds
		//FOR i = 2 TO t
		//K(i) = HMAC(PRK,(K(i-1),CTXinfo,i)) [key=PRK, data=(K(i-1),CTXinfo,i)]
		nextRounds(outLen, iv, hmacLength, outBytes, 
				intermediateOutBytes);
		
		//creates the secret key from the generated bytes
		return new SecretKeySpec(outBytes, "HKDF");
		
	}

}
