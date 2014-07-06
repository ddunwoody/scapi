/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2012 - SCAPI (http://crypto.biu.ac.il/scapi)
* This file is part of the SCAPI project.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
* 
* We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to
* http://crypto.biu.ac.il/SCAPI.
* 
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
*/


/**
 * PerfectUniversalFactory has a member of type FactoriesUtility to which it delegates the actual creation of the object. 
 * This ensures proper code re-use.The 
 * factories have two getObject methods to retrieve an algorithm compatible with the type; 
 * one specifies the provider and the other one relies on a default provider.
 */
package edu.biu.scapi.tools.Factories;


import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.primitives.universalHash.UniversalHash;

/** 
 * @author LabTest
 */
public final class UniversalHashFactory {
	private FactoriesUtility factoriesUtility;
	private static UniversalHashFactory instance = new UniversalHashFactory();

	
	/**
	 * Private constructor since this class is of the singleton pattern. 
	 * It creates an instance of FactoriesUtility and passes a predefined file names to the constructor
	 * of FactoriesUtility.
	 * 
	 */
	private UniversalHashFactory() {

		//create an instance of FactoriesUtility with the predefined file names.
		factoriesUtility = new FactoriesUtility("UniversalHashDefault.properties", "UniversalHash.properties");
		
	}
	
	/** 
	 * @param provider the required provider name
	 * @param algName the required algorithm name
	 * @return an object of type perfectUniversalHash class that was determined by the algName + provider
	 * @throws FactoriesException 
	 */
	public UniversalHash getObject(String algName, String provider) throws FactoriesException {
		
		return (UniversalHash) factoriesUtility.getObject(provider, algName);
	}

	/** 
	 * 
	 * @param algName the required algorithm name
	 * @return an object of type perfectUniversalHash class that was determined by the algName + the default provider for that algorithm.
	 * @throws FactoriesException 
	 */public UniversalHash getObject(String algName) throws FactoriesException {
		
		return (UniversalHash) factoriesUtility.getObject(algName);
	}

	/** 
	 * @return the singleton instance.
	 */
	public static UniversalHashFactory getInstance() {
		return instance;
	}
}
