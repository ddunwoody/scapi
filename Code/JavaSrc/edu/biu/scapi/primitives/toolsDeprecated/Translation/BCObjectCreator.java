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
