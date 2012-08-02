/**
* This file is part of SCAPI.
* SCAPI is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
* SCAPI is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
* You should have received a copy of the GNU General Public License along with SCAPI.  If not, see <http://www.gnu.org/licenses/>.
*
* Any publication and/or code referring to and/or based on SCAPI must contain an appropriate citation to SCAPI, including a reference to http://crypto.cs.biu.ac.il/SCAPI.
*
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
*
*/
/**
* This file is part of SCAPI.
* SCAPI is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
* SCAPI is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
* You should have received a copy of the GNU General Public License along with SCAPI.  If not, see <http://www.gnu.org/licenses/>.
*
* Any publication and/or code referring to and/or based on SCAPI must contain an appropriate citation to SCAPI, including a reference to http://crypto.cs.biu.ac.il/SCAPI.
*
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
*
*/
package edu.biu.scapi.primitives.prg.bc;

import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamCipher;

import edu.biu.scapi.exceptions.UnInitializedException;
import edu.biu.scapi.primitives.prg.PseudorandomGenerator;
import edu.biu.scapi.tools.Translation.BCParametersTranslator;

/**
 * A general adapter class of PRG for bouncy castle. <p>
 * This class implements the PRG functionality by passing requests to the adaptee interface StreamCigher.
 * A concrete prg such as RC4 represented in the class BcRC4only passes the RC4Engine object in the constructor.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 *
 */
public abstract class BcPRG implements PseudorandomGenerator {
	
	private SecretKey secretKey = null;	//secret key
	private SecureRandom random;
	private boolean isKeySet = false;
	private StreamCipher bcStreamCipher;	//the underlying stream cipher of bc
	private CipherParameters bcParams;		//the parameters for the underlying StreamCipher
		

	/** 
	 * Sets the StreamCipher of bc to adapt to.
	 * @param bcStreamCipher - the concrete StreamCipher of bc
	 */
	public BcPRG(StreamCipher bcStreamCipher) {
		//creates a random and call the other constructor
		this(bcStreamCipher, new SecureRandom());
	}
	
	/** 
	 * Sets the StreamCipher of bc to adapt to and the secureRandom object.
	 * @param bcStreamCipher - the concrete StreamCipher of bc
	 * @param random
	 */
	public BcPRG(StreamCipher bcStreamCipher, SecureRandom random) {
		this.bcStreamCipher = bcStreamCipher;
		this.random = random;
	}
	
	public void setKey(SecretKey secretKey) {
		
		//gets the BC keyParameter relevant to the secretKey
		bcParams = BCParametersTranslator.getInstance().translateParameter(secretKey);
		
		//initializes the underlying stream cipher. Note that the first argument is irrelevant and thus does not matter is true or false.
		bcStreamCipher.init(false, bcParams);
		
		//sets the key. Further initialization should be implemented in the derived concrete class.
		this.secretKey = secretKey;
		//marks this object as initialized
		isKeySet = true;
	}
	
	public boolean isKeySet(){
		return isKeySet;
	}
	
	/** 
	 * Returns the name of the algorithm through the underlying StreamCipher
	 * @return - the algorithm name
	 */
	public String getAlgorithmName() {
		
		return bcStreamCipher.getAlgorithmName();
	}

	/**
	 * This function is not supported in this implementation. Throws exception.
	 * @throws UnsupportedOperationException 
	 */
	public SecretKey generateKey(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException{
		throw new UnsupportedOperationException("To generate a key for this prg object use the generateKey(int keySize) function");
	}
	
	/**
	 * Generates a secret key to initialize this prg object.
	 * @param keySize is the required secret key size in bits 
	 * @return the generated secret key 
	 */
	public SecretKey generateKey(int keySize){
		//generate a random string of bits of length keySize, which has to be greater that zero. 
		
		//if the key size is zero or less - throw exception
		if (keySize < 0){
			throw new NegativeArraySizeException("key size must be greater than 0");
		}
		//creates a byte array of size keySize
		byte[] genBytes = new byte[keySize];

		//generates the bytes using the random
		//Do we need to seed random??
		random.nextBytes(genBytes);
		//creates a secretKey from the generated bytes
		SecretKey generatedKey = new SecretKeySpec(genBytes, "");
		return generatedKey;
		
	}
	
	/** 
	 * Streams the bytes using the underlying stream cipher.
	 * @param outBytes - output bytes. The result of streaming the bytes.
	 * @param outOffset - output offset
	 * @param outLen - the required output length
	 * @throws UnInitializedException if this object is not initialized
	 */
	public void getPRGBytes(byte[] outBytes, int outOffset,	int outLen){
		if (!isKeySet()){
			throw new IllegalStateException("secret key isn't set");
		}
		//checks that the offset and the length are correct
		if ((outOffset > outBytes.length) || ((outOffset + outLen) > outBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given output buffer");
		}
		
		/*
		 * BC generates bytes and does XOR between them to the given byte array. 
		 * In order to get the bytes without XOR we send a zeroes array to be XOR-ed with the generated bytes.
		 * Because XOR with zeroes returns the input to the XOR - we will get the generated bytes.
		 */
		
		//in array filled with zeroes
		byte[] inBytes = new byte[outLen];
		
		//out array filled with pseudorandom bytes (that were xored with zeroes in the in array)
		bcStreamCipher.processBytes(inBytes, 0, outLen, outBytes, outOffset);
	}


}
