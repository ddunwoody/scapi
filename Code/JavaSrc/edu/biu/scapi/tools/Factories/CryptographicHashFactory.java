package edu.biu.scapi.tools.Factories;
import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.primitives.hash.CryptographicHash;
/**
 * CollResFactory has a member of type FactoriesUtility to which it delegates the actual creation of the object. 
 * This ensures proper code re-use.The 
 * factories have two getObject methods to retrieve an algorithm compatible with the type; 
 * one specifies the provider and the other one relies on a default provider.
 * 
*  @author LabTest
 */
public final class CryptographicHashFactory {
	private FactoriesUtility factoriesUtility;
	private static CryptographicHashFactory instance = new CryptographicHashFactory();

	/**
	 * Private constructor since this class is of the singleton pattern. 
	 * It creates an instance of FactoriesUtility and passes a predefined file names to the constructor
	 * of FactoriesUtility.
	 * 
	 */
	private CryptographicHashFactory() {
	
		//create an instance of FactoriesUtility with the predefined file names.
		factoriesUtility = new FactoriesUtility("CryptographicHashDefault.properties", "CryptographicHash.properties");
		
	}
	
	/** 
	 * @param provider the required provider name
	 * @param algName the required algorithm name
	 * @return an object of type TargetCollisionResistant class that was determined by the algName + provider
	 * @throws FactoriesException 
	 */
	public CryptographicHash getObject(String algName, String provider) throws FactoriesException {
		
		return (CryptographicHash) factoriesUtility.getObject(provider, algName);
	}

	/** 
	 * 
	 * @param algName the required algorithm name
	 * @return an object of type TargetCollisionResistant class that was determined by the algName + the default provider for that algorithm
	 * @throws FactoriesException 
	 */
	public CryptographicHash getObject(String algName) throws FactoriesException {
		
		return (CryptographicHash) factoriesUtility.getObject(algName);
	}

	/** 
	 * @return the singleton instance.
	 */
	public static CryptographicHashFactory getInstance() {
		return instance;

	}
}