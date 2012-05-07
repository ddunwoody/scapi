/**
 * TrapdoorPermutationFactory has a member of type FactoriesUtility to which it delegates the actual creation of the object. 
 * This ensures proper code re-use.The 
 * factories have two getObject methods to retrieve an algorithm compatible with the type; 
 * one specifies the provider and the other one relies on a default provider.
 */

package edu.biu.scapi.tools.Factories;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.primitives.trapdoorPermutation.TrapdoorPermutation;

/** 
 * @author LabTest
 */
public final class TrapdoorPermutationFactory {
	private FactoriesUtility factoriesUtility;
	private static TrapdoorPermutationFactory instance = new TrapdoorPermutationFactory();

	
	/**
	 * Private constructor since this class is of the singleton pattern. 
     * It creates an instance of FactoriesUtility and passes a predefined file names to the constructor
     * of FactoriesUtility.
	 * 
	 */
	private TrapdoorPermutationFactory() {

		//create an instance of FactoriesUtility with the predefined file names.
		factoriesUtility = new FactoriesUtility("TPDefault.properties", "TP.properties");
		
	}
	
	
	/** 
	 * @param provider the required provider name
	 * @param algName the required algorithm name
	 * @return an object of type TrapdoorPermutation class that was determined by the algName + provider
	 * @throws FactoriesException 
	 */
	public TrapdoorPermutation getObject(String algName, String provider) throws FactoriesException {
		
		return (TrapdoorPermutation) factoriesUtility.getObject(provider, algName);
	}

	/** 
	 * 
	 * @param algName the required algorithm name
	 * @return an object of type TrapdoorPermutation class that was determined by the algName + the default provider for that algorithm
	 * @throws FactoriesException 
	 */
	public TrapdoorPermutation getObject(String algName) throws FactoriesException {
		
		return (TrapdoorPermutation) factoriesUtility.getObject(algName);
	}

	/** 
	 * @return the singleton instance.
	 */
	public static TrapdoorPermutationFactory getInstance() {
		return instance;
	}
}