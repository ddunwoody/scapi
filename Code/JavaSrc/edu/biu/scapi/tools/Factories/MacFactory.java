/**
 * MacFactory has a member of type FactoriesUtility to which it delegates the actual creation of the object. 
 * This ensures proper code re-use.The 
 * factories have two getObject methods to retrieve an algorithm compatible with the type; 
 * one specifies the provider and the other one relies on a default provider.
 */
package edu.biu.scapi.tools.Factories;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.midLayer.symmetricCrypto.mac.Mac;

public final class MacFactory {
	private static MacFactory instance = new MacFactory();;
	private FactoriesUtility factoriesUtility;

	
	/**
	 * Private constructor since this class is of the singleton pattern. 
     * It creates an instance of FactoriesUtility and passes a predefined file names to the constructor
     * of FactoriesUtility.
	 * 
	 */
	private MacFactory() {

		//create an instance of FactoriesUtility with the predefined file names.
		factoriesUtility = new FactoriesUtility("MacDefault.properties", "Mac.properties");
		
	}
	
	
	/** 
	 * @param provider the required provider name
	 * @param algName the required algorithm name
	 * @return an object of type Mac class that was determined by the algName + provider
	 * @throws FactoriesException 
	 */
	public Mac getObject(String algName, String provider) throws FactoriesException {
		
		return (Mac) factoriesUtility.getObject(provider, algName);
	}

	/** 
	 * 
	 * @param algName the required algorithm name
	 * @return an object of type Mac class that was determined by the algName + the default provider for that algorithm.
	 * @throws FactoriesException 
	 */
	public Mac getObject(String algName) throws FactoriesException {
		
		return (Mac) factoriesUtility.getObject(algName);
	}

	/** 
	 * @return the singleton instance.
	 */
	public static MacFactory getInstance() {
		return instance;

	}
	
	
}