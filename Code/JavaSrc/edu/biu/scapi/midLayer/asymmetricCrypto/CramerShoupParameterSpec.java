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
package edu.biu.scapi.midLayer.asymmetricCrypto;

import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;


/**
 * This class holds parameters needed to initialize an instance of the Cramer-Shoup encryption algorithm.<p>
 * Since Cramer-Shoup is based on a Dlog Group and on a Cryptographic Hash, parameters needed to initialize those underlying parameters are an essential part of this class.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class CramerShoupParameterSpec implements AlgorithmParameterSpec {
	//Cramer-Shoup algo needs a source of randomness to be able to work.
	SecureRandom random;
	//Parameters to initialize the Dlog Group used by Cramer-Shoup
	//Do we want to hold the group params as a variable of type GroupParams or AlgorithmParameterSpec
	AlgorithmParameterSpec groupParams;

	public CramerShoupParameterSpec(SecureRandom random, AlgorithmParameterSpec groupParams) {
		this.random = random;
		this.groupParams = groupParams;
	}
	
	public SecureRandom getSecureRandom(){
		return random;
	}
	public AlgorithmParameterSpec getDlogGroupParams(){
		return groupParams;
	}
}
