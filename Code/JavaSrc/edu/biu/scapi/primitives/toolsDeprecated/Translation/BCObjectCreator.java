/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2012 - SCAPI (http://crypto.biu.ac.il/scapi)
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
package edu.biu.scapi.tools.Translation;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.StreamCipher;

import edu.biu.scapi.primitives.crypto.trapdoor_permutation.TrapdoorPermutation;
import edu.biu.scapi.primitives.crypto.prf.PseudorandomPermutation;
import edu.biu.scapi.primitives.crypto.hash.TargetCollisionResistant;
import edu.biu.scapi.primitives.crypto.prg.PseudorandomGenerator;

/** 
  * @author LabTest
  */
public class BCObjectCreator {
	private BCClassTranslator bCClassTranslator;
	private BCParametersTranslator bCParametersTranslator;
	private static final BCObjectCreator objectCreator = new BCObjectCreator();//singleton

	/**
	 * Empty constructor should be private since this class is singleton and we want to prevent user creation
	 * of this class
	 */
	private BCObjectCreator(){
		bCClassTranslator = BCClassTranslator.getInstance();
		bCParametersTranslator = BCParametersTranslator.getInstance();
		
	};
	
	/** 
	 * @return the singleton object
	 */
	public static BCObjectCreator getInstance() {
		return objectCreator;
		
	}
	
	/** 
	 * @param trapdoorPermutation
	 * @return
	 * @throws ClassNotFoundException 
	 * @throws IllegalAccessException 
	 * @throws InstantiationException 
	 */
	public AsymmetricBlockCipher getBCAsymmetricBlockCipher(
			TrapdoorPermutation trapdoorPermutation) throws InstantiationException, IllegalAccessException, ClassNotFoundException {

		//get the asymmetric block cipher of bc via the name of the trapdoor permutation
		AsymmetricBlockCipher asymmetricBlockCipher = bCClassTranslator.loadBCAsymetricBlockCipher(trapdoorPermutation.getAlgorithmName());
		
		//get the parameters to init the cipher.
		//CipherParameters params = bCParametersTranslator.translateParameter(trapdoorPermutation.getPubKeySpec(), trapdoorPermutation.getParams());
		
		return asymmetricBlockCipher;
	}

	/** 
	 * @param name
	 * @param params
	 * @return
	 */
	public AsymmetricBlockCipher getBCAsymmetricBlockCipher(String name,
			AlgorithmParameterSpec params) {
		// begin-user-code
		// TODO Auto-generated method stub
		return null;
		// end-user-code
	}

	/** 
	 * @param prp
	 * @return
	 */
	public BlockCipher getBCBlockCipher(PseudorandomPermutation prp) {
		// begin-user-code
		// TODO Auto-generated method stub
		return null;
		// end-user-code
	}

	/** 
	 * @param params
	 * @param name
	 * @return
	 */
	public BlockCipher getBCBlockCipher(AlgorithmParameterSpec params,
			String name) {
		// begin-user-code
		// TODO Auto-generated method stub
		return null;
		// end-user-code
	}

	/** 
	 * @param hash - a hash object from which we can take attributes to pass to the classTranslator
	 * @return
	 * @throws ClassNotFoundException 
	 * @throws IllegalAccessException 
	 * @throws InstantiationException 
	 */
	public Digest getBCDigest(TargetCollisionResistant hash) throws InstantiationException, IllegalAccessException, ClassNotFoundException {
		
		//pass the name of the digest through the name of the hash
		return bCClassTranslator.loadBCDigest(hash.getAlgorithmName());
		
	}

	/** 
	 * @param name - the name of the digest to load
	 * @param params - auxilary parameters to pass
	 * @return
	 * @throws ClassNotFoundException 
	 * @throws IllegalAccessException 
	 * @throws InstantiationException 
	 */
	public Digest getBCDigest(String name, AlgorithmParameterSpec params) throws InstantiationException, IllegalAccessException, ClassNotFoundException {

		//pass the name of the digest 
		return bCClassTranslator.loadBCDigest(name);
	}

	/** 
	 * @param name
	 * @param params
	 * @return
	 */
	public StreamCipher getBCStreamCipher(String name,
			AlgorithmParameterSpec params) {
		// begin-user-code
		// TODO Auto-generated method stub
		return null;
		// end-user-code
	}

	/** 
	 * @param prg - a PseudorandomGenerator object from which we can take attributes to pass to the classTranslator
	 * @return - The related StreamCipher
	 */
	public StreamCipher getBCStreamCipher(PseudorandomGenerator prg) {
		
		//get the related StreamCipher
		
		StreamCipher streamCipher = bCClassTranslator.loadBCStreamCipher(prg.getAlgorithmName());
		
		//translate the key and parameters to suit bc parameters
		CipherParameters bcParams = bCParametersTranslator.translateParameter(prg.getSecretKey(), prg.getParams());
		
		//init the bc stream cipher
		streamCipher.init(false, bcParams);
		
		return streamCipher;
		
	}

	
}
