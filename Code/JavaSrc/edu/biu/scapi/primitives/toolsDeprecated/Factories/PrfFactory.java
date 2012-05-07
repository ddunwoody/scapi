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