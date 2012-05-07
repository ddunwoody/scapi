package edu.biu.scapi.tools.Factories;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.paddings.PaddingScheme;

public class PaddingFactory {
	private static PaddingFactory instance = new PaddingFactory();
	private FactoriesUtility factoriesUtility;

	
	/**
	 * Private constructor since this class is of the singleton pattern. 
     * It creates an instance of FactoriesUtility and passes a predefined file names to the constructor
     * of FactoriesUtility.
	 * 
	 */
	private PaddingFactory() {

		//create an instance of FactoriesUtility with the predefined file names.
		factoriesUtility = new FactoriesUtility("PaddingDefault.properties", "Padding.properties");
		
	}
	
	
	/** 
	 * @param provider the required provider name
	 * @param algName the required algorithm name
	 * @return an object of type AsymmetricEnc class that was determined by the algName + provider
	 * @throws FactoriesException 
	 */
	public PaddingScheme getObject(String algName, String provider) throws FactoriesException {
		
		return (PaddingScheme) factoriesUtility.getObject(provider, algName);
	}

	/** 
	 * 
	 * @param algName the required algorithm name
	 * @return an object of type AsymmetricEnc class that was determined by the algName + the default provider for that algorithm.
	 * @throws FactoriesException 
	 */
	public PaddingScheme getObject(String algName) throws FactoriesException {
		
		return (PaddingScheme) factoriesUtility.getObject(algName);
	}

	/** 
	 * @return the singleton instance.
	 */
	public static PaddingFactory getInstance() {
		return instance;

	}
}
