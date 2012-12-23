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


package edu.biu.scapi.tools.Factories;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.StreamCipher;

import edu.biu.scapi.exceptions.FactoriesException;

/** 
 * @author LabTest
 */
/**
 * Suppose we wish to wrap a higher-level cryptographic element that uses a primitive interface in its inner implementation. 
 * For example, HMAC of BC holds a Digest interface but requires a specific digest to invoke its main functions. 
 * However, the users of our tool are not familiar with the classes of BC. Yet if we wish to wrap this class, 
 * we will need to instantiate a concrete Digest (specified by the user) to the wrapped BcHMAC. 
 * The aim of the BCFactory is to translate from an algorithm name string to an external library instance. 
 * For example, in BcHMAC the user passes a hash name that eventually will be translated to a digest. 
 * If the user passed the "SHA1" string, the translation tool generates the related SHA1 digest.
 */
public final class BCFactory {
	private FactoriesUtility factoriesUtility;
	private static BCFactory instance = new BCFactory();//singleton

	
	/**
	 * Private constructor since this class is of the singleton pattern. 
     * It creates an instance of FactoriesUtility and passes a predefined file name to the constructor
     * of FactoriesUtility.
	 * 
	 */
	private BCFactory() {

		//create an instance of FactoriesUtility with the predefined file name.  
		factoriesUtility = new FactoriesUtility(null, "BC.properties");
		
	}
	
	/** 
	 * Returns the equivalent BC block cipher according to the specified name.
	 * @param name the name of the pseudo random permutation equivalent to the BC block cipher
	 * @return BC <code>BlockCipher</code> object
	 * @throws FactoriesException 
	 */
	public BlockCipher getBlockCipher(String name) throws FactoriesException {
		
		return (BlockCipher) factoriesUtility.getObject("BC", name);
	}

	/** 
	 * Returns the equivalent BC asymmetric block cipher according to the specified name.
	 * @param name the name of the trapdoor permutation equivalent to the BC asymmetric block cipher
	 * @return BC <code>AsymmetricBlockCipher</code> object
	 * @throws FactoriesException 
	 */
	public AsymmetricBlockCipher getAsymetricBlockCipher(String name) throws FactoriesException {
		
		return (AsymmetricBlockCipher) factoriesUtility.getObject("BC", name);
	}

	/** 
	 * Returns the equivalent BC digest according to the specified name.
	 * @param name the name of the collision resistant hash equivalent to the BC digest cipher
	 * @return BC <code>Digest</code> object
	 * @throws FactoriesException 
	 */
	public Digest getDigest(String name) throws FactoriesException {
		
		return (Digest) factoriesUtility.getObject("BC", name);
	}

	/** 
	 * Returns the equivalent BC stream cipher according to the specified name. 
	 * @param name the name of the pseudo random generator equivalent to the BC stream cipher
	 * @return BC <code>StreamCipher</code> object
	 * @throws FactoriesException 
	 */
	public StreamCipher getStreamCipher(String name) throws FactoriesException {
		
		return (StreamCipher) factoriesUtility.getObject("BC", name);
	}

	/** 
	 * @return the singleton instance
	 */
	public static BCFactory getInstance() {
		
		return instance;
		
	}
}
