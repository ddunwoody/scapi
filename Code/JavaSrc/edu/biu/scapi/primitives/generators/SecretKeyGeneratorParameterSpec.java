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
package edu.biu.scapi.primitives.generators;

import java.security.spec.AlgorithmParameterSpec;

/**
 * This class is the parameters for the secret key generation.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SecretKeyGeneratorParameterSpec implements AlgorithmParameterSpec{

	private int keySize = 0;				//the required key size
	private String algorithmName = null;	//the algorithm name of the required key
	
	/** 
	 * Constructor that gets the size and the algorithm name and sets them.
	 * @param keySize the required key size
	 * @param name the algorithm name of the key
	 */
	public SecretKeyGeneratorParameterSpec(int keySize, String name){
		//sets the parameters
		this.keySize = keySize;
		algorithmName = name;
	}
	
	/**
	 * @return the required key size
	 */
	public int getKeySize(){
		return keySize;
	}
	
	/**
	 * @return algorithm name of the key
	 */
	public String getAlgorithmName(){
		return algorithmName;
	}
}
