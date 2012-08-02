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
package edu.biu.scapi.primitives.prg;

import java.security.spec.AlgorithmParameterSpec;


import javax.crypto.SecretKey;

import edu.biu.scapi.exceptions.UnInitializedException;

/** 
 * This class implements some common functionality of PRG.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public abstract class PseudorandomGeneratorAbs implements PseudorandomGenerator {
	
	protected SecretKey secretKey = null;			//secret key
	protected AlgorithmParameterSpec params = null; //algorithm parameters
	protected boolean isInitialized = false;		//until init is called set to false.

	public void init(SecretKey secretKey) {

		//init the key. Further initialization should be implemented in the derived concrete class.
		this.secretKey = secretKey;
		//marks this object as initialized
		isInitialized = true;
	}

	public void init(SecretKey secretKey, AlgorithmParameterSpec params) {

		//init the parameters. Further initialization should be implemented in the derived concrete class.
		this.secretKey = secretKey;
		this.params = params;
		//marks this object as initialized
		isInitialized = true;
	}

	public boolean isInitialized(){
		return isInitialized;
	}
	
	public AlgorithmParameterSpec getParams() throws UnInitializedException {
		if (!isInitialized()){
			throw new UnInitializedException();
		}
		return params;
	}

}
