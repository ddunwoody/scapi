package edu.biu.scapi.tools.Factories;

import java.math.BigInteger;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.primitives.trapdoorPermutation.TPElement;

public class TPElementFactory {

	
	private FactoriesUtility factoriesUtility;
	private static TPElementFactory instance = new TPElementFactory();

	/**
	 * PrgFactory - private constructor since this class is of the singleton pattern. 
     * 	     		It creates an instance of FactoriesUtility and passes a predefined file names to the constructor
     * 		    	of FactoriesUtility.
	 * 
	 */
	private TPElementFactory() {

		//create an instance of FactoriesUtility with the predefined file names.
		factoriesUtility = new FactoriesUtility("TPElementDefault.properties", "TPElement.properties");	
	}
	
	/** 
	 * @param provider - the required provider name
	 * @param algName - the required algorithm name
	 * @param modN - the required modulus to the TPElement constructor
	 * @return an object of type PseudorandomGenerator class that was determined by the algName + provider
	 * @throws FactoriesException 
	 */
	public TPElement getRandomElement(String algName, String provider, BigInteger modN) throws FactoriesException {
		
		Object[] params = new Object[1];
		params[0] = modN;
		return (TPElement) factoriesUtility.getObject(provider, algName, params);
	}

	/** 
	 * @param algName - the required algorithm name
	 * @param modN - the required modulus to the TPElement constructor
	 * @return an object of type PseudorandomGenerator class that was determined by the algName + the default provider for that algorithm.
	 * @throws FactoriesException 
	 */
	public TPElement getRandomElement(String algName, BigInteger modN) throws FactoriesException {
		
		Object[] params = new Object[1];
		params[0] = modN;
		return (TPElement) factoriesUtility.getObject(algName, params);
	}

	/** 
	 * @param provider - the required provider name
	 * @param algName - the required algorithm name
	 * @param modN - the required modulus to the TPElement constructor
	 * @param x - the required value to the TPElement constructor
	 * @return an object of type PseudorandomGenerator class that was determined by the algName + provider
	 * @throws FactoriesException 
	 */
	public TPElement getElement(String algName, String provider, BigInteger modN, BigInteger x) throws FactoriesException {
		
		Object[] params = new Object[2];
		params[0] = modN;
		params[1] = x;
		return (TPElement) factoriesUtility.getObject(provider, algName, params);
	}

	/** 
	 * @param algName - the required algorithm name
	 * @param modN - the required modulus to the TPElement constructor
	 * @param x - the required value to the TPElement constructor
	 * @return an object of type PseudorandomGenerator class that was determined by the algName + the default provider for that algorithm.
	 * @throws FactoriesException 
	 */
	public TPElement getElement(String algName, BigInteger modN, BigInteger x) throws FactoriesException {
		
		Object[] params = new Object[2];
		params[0] = modN;
		params[1] = x;
		return (TPElement) factoriesUtility.getObject(algName, params);
	}
	/** 
	 * @return the singleton instance.
	 */
	public static TPElementFactory getInstance() {
		return instance;
	}
}
