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
package edu.biu.scapi.tools.Factories;

import edu.biu.scapi.primitives.crypto.hash.TargetCollisionResistant;
import edu.biu.scapi.primitives.crypto.prf.PseudorandomFunction;

public class PrfFactory {
	private static PrfFactory instance = new PrfFactory();
	private FactoriesUtility factoriesUtility;

	
	/**
	 * PrfFactory - private constructor since this class is of the singleton pattern. 
     * 	     		It creates an instance of FactoriesUtility and passes a predefined file names to the constructor
     * 		    	of FactoriesUtility.
	 * 
	 */
	private PrfFactory() {

		//create an instance of FactoriesUtility with the predefined file names.
		FactoriesUtility factoriesUtility = new FactoriesUtility("PrfDefault.properties", "Prf.properties");
		
	}
	
	
	/** 
	 * @param provider - the required provider name
	 * @param algName - the required algorithm name
	 * @return an object of type PseudorandomFunction class that was determined by the algName + provider
	 */
	public PseudorandomFunction getObject(String algName, String provider) {
		
		return (PseudorandomFunction) factoriesUtility.getObject(provider, algName);
	}

	/** 
	 * 
	 * @param algName - the required algorithm name
	 * @return an object of type PseudorandomFunction class that was determined by the algName + the default provider for that algorithm.
	 */
	public PseudorandomFunction getObject(String algName) {
		
		return (PseudorandomFunction) factoriesUtility.getObject(algName);
	}

	/** 
	 * @return the singleton instance.
	 */
	public static PrfFactory getInstance() {
		return instance;
	}
}
