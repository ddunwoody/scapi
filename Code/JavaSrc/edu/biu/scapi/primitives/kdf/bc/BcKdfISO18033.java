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


package edu.biu.scapi.primitives.kdf.bc;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.DerivationParameters;
import org.bouncycastle.crypto.generators.BaseKDFBytesGenerator;
import org.bouncycastle.crypto.generators.KDF1BytesGenerator;
import org.bouncycastle.crypto.params.ISO18033KDFParameters;
import org.bouncycastle.crypto.params.KDFParameters;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.primitives.kdf.KeyDerivationFunction;
import edu.biu.scapi.tools.Factories.BCFactory;

/**
 * This is a concrete class of KDF for ISO18033. This class wraps the implementation of bouncy castle.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 *
 */
public class BcKdfISO18033 implements KeyDerivationFunction {

	BaseKDFBytesGenerator bcKdfGenerator; // the adaptee kdf of BC
	
	/**
	 * creates the related bc kdf. Retrieve the related digest out of the given hash name.
	 * @param hash name of the underlying hash to use
	 * @throws FactoriesException in case of error while creating the object
	 */
	public BcKdfISO18033(String hash) throws FactoriesException{
		//creates a digest through the factory and passes it to the KDF
		bcKdfGenerator = new KDF1BytesGenerator(BCFactory.getInstance().getDigest(hash));	
	}
	
	/**
	 * creates the related bc kdf, with the given hash
	 * @param hash - the underlying collision resistant hash
	 * @throws FactoriesException in case of error while creating the object
	 */
	public BcKdfISO18033(CryptographicHash hash) throws FactoriesException{
		
		//creates a digest of the given hash type through the factory and passes it to the KDF
		bcKdfGenerator = new KDF1BytesGenerator(BCFactory.getInstance().getDigest(hash.getAlgorithmName()));
	}
	
	public SecretKey deriveKey(byte[] entropySource, int inOff, int inLen, int outLen){
		//calls the generateKey with iv=null
		return deriveKey(entropySource, inOff, inLen, outLen, null);
		
	}
	
	public SecretKey deriveKey(byte[] entropySource, int inOff, int inLen, int outLen, byte[] iv){
		
		//checks that the offset and length are correct
		if ((inOff > entropySource.length) || (inOff+inLen > entropySource.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given input buffer");
		}
	
		//generates the related derivation parameter for bc with the seed and iv
		bcKdfGenerator.init(generateParameters(entropySource,iv));
		
		byte[] derivatedKey = new byte[outLen];
		//generates the actual key bytes and puts it in the output array
		bcKdfGenerator.generateBytes(derivatedKey, 0, outLen);
		
		return new SecretKeySpec(derivatedKey, "KDF");
		
	}
		
	
	/**
	 * Generates the bc related parameters of type DerivationParameters
	 * @param shared the input key 
	 * @param iv
	 */
	private DerivationParameters generateParameters(byte[] shared, byte[] iv){
		
		if(iv==null){//iv is not provided
			
			return new ISO18033KDFParameters(shared);
		}
		else{ //iv is provided. Passes to the KDFParameters
			return new KDFParameters(shared, iv);
		}
		
	}

	
}
