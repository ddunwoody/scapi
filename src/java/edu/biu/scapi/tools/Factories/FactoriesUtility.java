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


package edu.biu.scapi.tools.Factories;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.Properties;
import java.util.Set;
import java.util.Vector;
import java.util.logging.Level;


import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.generals.Logging;

/* 
 * @author LabTest
 */
/*
 * The FactoriesUtility class as its name indicates is a utility class used by all the factories
 * and only by the factories since it is package private and belongs to the  edu.biu.scapi.tools.Factories package 
 * The actual creation of the object is done with this class in the public function getObject
 * All the factories call this method and cast the created object to the actual type they need to return 
 */
class FactoriesUtility {
	private Properties defaultProviderMap;
	private Properties algsInType;
	
	private static final String PROPERTIES_FILES_PATH = "/propertiesFiles/";

	
	/* 
	 * Loads the files to the properties attributes.
	 * @param defaultProviderFileName the file name from which to load the default provider properties from. 
	 * 									*Note that this can be null. for example the BCFactory does not need to pass
	 * 									 default provider for each implementation. 
	 * @param algsInTypeFileName the file name from which to load the algorithms in type properties from
	 */
	public FactoriesUtility(String defaultProviderFileName,
			String algsInTypeFileName) {
		
		try {
			//load algorithms classes
			loadAlgsInType(algsInTypeFileName);
			
			//if this class is used by a class that does not need default provider, it will not pass a name to such a file
			if(defaultProviderFileName!=null)
				//load default provider names for each algorithm name
				loadDefaultProvider(defaultProviderFileName);
		} catch (FileNotFoundException e) {
			
			Logging.getLogger().log(Level.WARNING, e.toString());
		} catch (IOException e) {
			
			Logging.getLogger().log(Level.WARNING, e.toString());
		}
	}
	
	/* 
	 * parseAlgNames : The string algName should be of the form “alg1Name(alg2Name, …,algnName)”, where n can be any number greater than zero. 
	 * (If n = zero, then AlgDetails.Name = null and AlgDetails.tail = null. If n = 1 then  AlgDetails.Name = “alg1” and AlgDetails.params=null. 
	 * If n >=2 then AlgDetails.Name = alg1 and AlgDetails.tail = [alg2Name , …,algnName)])
	 * •	Parse the string and return the following:
	 * o	If n = 0, then AlgDetails.name = null and AlgDetails.params = null. 
	 * o	If n = 1, then AlgDetails.name = “alg1” and AlgDetails.params =null. 
	 * If n >=2, then AlgDetails.name = “alg1” and AlgDetails.params = [alg2Name, …,algnName]
	 * 
	 * @param algNames a string of the form "alg1Name(alg2Name,alg3Name(alg4Name, alg5Name)" where alg1 is the main algorithm which takes
	 * 					 other algorithms as parameters (complex algorithm) and alg3 is also a complex algorithm that takes
	 * 					 alg4 and alg5 simple algorithms as parameters. 
	 * @return
	 */
	private AlgDetails parseAlgNames(String algNames) {

		//create a new algDetails object to return
		AlgDetails algDetails = new AlgDetails();
		
		//use the parser to separate the string into the main algorithm and the params 
		AlgorithmStringParser parser = new AlgorithmStringParser(algNames);
		
		//get the main algorithm
		algDetails.name = parser.getAlgName();
		
		//get the parameters
		algDetails.params = parser.getParsedParams();
		
		return algDetails;
		
	}

	/* 
	 * This function checks that the algorithm requested is in effect an algorithm within the cryptographic
	 * type for which the object is being created.
	 * @param algName the algorithm for which to check validity
	 * @return true if the algorithm exists in the algsInTypeMap, else false.
	 */
	private boolean checkAlgorithmsValidityForType(String algName) {
		
		boolean valid = false;
		Set<String> setOfKeys = algsInType.stringPropertyNames();
		for(String key: setOfKeys){
			if(key.contains(algName)){
				valid  = true;
				break;
			}
		}
		return valid;
	}

	/* This function checks that the algorithm requested is implemented by the provider specified
	 * @param provider name of possibly implementing provider
	 * @param algName the algorithm for which to check validity
	 * @return true if the algorithm is implemented by the specified provider, else false.
	 */
	private boolean checkProviderImplementationOfAlgorithm(String provider, String algName) {

		return algsInType.containsKey(provider + algName);
	}

	
	/* 
	 * @param provider the required provider of the requested algorithm
	 * @param algName the algorithm name
	 * @return the concatenation of provider+algorithm.
	 */
	private String prepareKey(String provider, String algName) {
		
		return provider+algName;

	}

	/*
	 * Loads the names of the algorithms concatenated to the provider and the full name of the corresponding implementing JAVA class
	 * For example, for the PRF family the loaded file could like this:
	 *  # prf classes
	 *	BCHMac = edu.biu.scapi.primitives.prf.bc.BcHMACC
	 *  SCIteratedPrfVarying = edu.biu.scapi.primitives.prf.IteratedPrfVarying
	 *  BCAES = edu.biu.scapi.primitives.prf.bc.BcAES
	 *   
	 * @param algsInTypeFileName the name of the file to load
	 * @throws IOException 
	 * @throws FileNotFoundException  
	 */
	private void loadAlgsInType(String algsInTypeFileName) throws FileNotFoundException, IOException {
		
		algsInType = new Properties();
		//Load the algsInTypeFileName file
		//Instead of loading the plain file, which only works from outside a jar file, we load it as a resource 
		//that can also work from within a jar file. The path from which we load the properties file from is from now under bin\propertiesFiles.
		InputStream in=  (InputStream) getClass().getResourceAsStream(PROPERTIES_FILES_PATH + algsInTypeFileName);
		algsInType.load(in);
		
	}

	/*
	 * Loads the names of the algorithms with the corresponding default providers 
	 * For example, for the PRF family the loaded file could look like this:
	 *  # prf default provider 
	 *  HMac = BC
	 *  IteratedPrfVarying = SC
	 *  AES = BC
	 * 
	 * @param defaultProviderFileName the name of the file to load
	 * @throws IOException 
	 * @throws FileNotFoundException  
	 */
	private void loadDefaultProvider(String defaultProviderFileName) throws FileNotFoundException, IOException {
		
		//instantiate the default provider properties
		defaultProviderMap = new Properties();
        
		//Load the defaultProviderFileName file
		//Instead of loading the plain file, which only works from outside a jar file, we load it as a resource 
		//that can also work from within a jar file. The path from which we load the properties file from is from now under bin\propertiesFiles.
		InputStream in=  (InputStream) getClass().getResourceAsStream(PROPERTIES_FILES_PATH + defaultProviderFileName);
		
		defaultProviderMap.load(in);
			
	}

	/* 
	 * This function may return different libraries for different algorithms. 
	 * For example, it may return "Crypto++" when requesting a Rabin trapdoor permutation and "BC" when requesting an AES implementation. 
	 * The decision on which implementation to return will be based on the available implementations, 
	 * on performance and other relevant reasons. 
	 * 
	 * @param algName the algorithm name to get the default provider for
	 * @return the default provider for the algorithm specified with the key algName
	 */
	private String getDefaultImplProvider(String algName) {
		
		//get the parsed algorithm details to have name and params
		AlgDetails algDetails = parseAlgNames(algName);
		
		//get the provider for the main algorithm
		return defaultProviderMap.getProperty(algDetails.name);
	}

	/* 
	 * pseudocode:
	 * This function returns an Object instantiation of algName algorithm for the specified provider.
	 * •	Check validity of AlgDetails.name. If not valid, throw exception.
	 * •	Prepare key for map by concatenating provider + algName.
	 * •	Get relevant class name from properties map with the key obtained.
	 * •	Get an object of type Class representing our algorithm. (Class algClass).
	 * •	Retrieve a Constructor of algClass that accepts t parameters of type String, while t=tailVector.length.
	 * •	Create an instance of type algClass by calling the above Constructor. Pass as a parameter the “tailVector” in AlgDetails. The call Constructor.newInstance returns an object of type Object. (For example, if algName is a series of algorithms: "HMAC(SHA1)", the function creates an HMAC object and passes the tail – "SHA1" to the instance of HMAC. HMAC should be a class that takes as argument a string and in its constructor uses the factories to create the hash object. In this case, where there is a tail, the getObject function passes the String "SHA1" by retrieving a constructor that gets a String. If there is no such constructor, an exception will be thrown). 
	 * •    Return the object created.
	 *
	 * @param provider the required provider name
	 * @param algName the required algorithm name
	 * @param params - the required parameters to the algorithm 
	 * @return an object of the class that was determined by the algName + provider
	 */
	public Object getObject(String provider, String algName, Object[] params) throws FactoriesException	{
		
		//check that the algorithm requested belongs to the cryptographic type for which the object is being created
		boolean valid = checkAlgorithmsValidityForType(algName);
		//if invalid throw IllegalArgumentException exception
		if(!valid){
			throw (new IllegalArgumentException("This factory does not support the algorithm: " + algName));
		}
		
		//check that there exist an implementation of the requested algorithm by the requested provider 
		valid = checkProviderImplementationOfAlgorithm(provider, algName);
		//if invalid throw IllegalArgumentException exception
		if(!valid){
			throw (new IllegalArgumentException("Algorithm " + algName + " is not supported for provider " + provider));
		}
		
		//get the key as written in the property file
		String keyToMap = prepareKey(provider, algName);
		
		//get the related algorithm class name
		String className = algsInType.getProperty(keyToMap);
		Class algClass  = null;			//will hold an Object of type Class representing our alg class
		Object newObj = null;			//will the final create algorithm object
		try {
			
			//get the class object thru the name of the algorithm class
			algClass = Class.forName(className);
	
			//fill the classes of strings with the length of the vector. This will ensure that we get the right/relevant
			//constructor
			int size = params.length;
			Class[] classes = new Class[size]; 
			//fill the array with String classes
			for(int i=0;i<size;i++){
				classes[i] = params[i].getClass();
			}
			//get the constructor that has <code>classes.length</code> number of arguments of string type  
			Constructor constructor = algClass.getConstructor(classes);
			
			
			//prepare parameters for constructor:
			//get the vector of parameters from the algorithm details object.
			//create an instance of type algClass by calling the obtained constructor:
			//NOTE (Secure coding) : The command newInstance with a parameter contains a potential security risk of creating undesired objects
			//however, the parameters passed to the newInstance function are only those of algorithms we allow. That is, the classes that 
			//can be created here are limited and controlled.
			 newObj = constructor.newInstance(params);
		//When JAVA SE7 will be available to use with the Eclipse IDE we can change the following ugly block of catches to the
		//new, more elegant form  : catch ( SecurityException | NoSuchMethodException | ClassNotFoundException | IllegalArgumentException | 
		//								    InstantiationException | IllegalAccessException | InvocationTargetException e)
		} catch (SecurityException e) {
			throw new FactoriesException(e);
		} catch (NoSuchMethodException e) {
			throw new FactoriesException(e);
		} catch (ClassNotFoundException e) {
			throw new FactoriesException(e);
		} catch (IllegalArgumentException e) {
			throw new FactoriesException(e);
		} catch (InstantiationException e) {
			throw new FactoriesException(e);
		} catch (IllegalAccessException e) {
			throw new FactoriesException(e);
		} catch (InvocationTargetException e) {
			throw new FactoriesException(e);
		}
		
		//Finally, if we got to this, return the newly created object!!
		return  newObj;
		
	}	
	
	

	/* 
	 * @param provider - the required provider name
	 * @param algName - the required algorithm name
	 * @return an object of the class that was determined by the algName + the provider for that algorithm.
	 */
	public Object getObject(String provider, String algName) throws FactoriesException {
	
		//get the parsed algorithm details to have name and params
		AlgDetails algDetails = parseAlgNames(algName);
		
		
		return getObject(provider, algDetails.name, algDetails.params.toArray());
	}
	
	/* 
	 * 
	 * @param algName the required algorithm name
	 * @return an object of the class that was determined by the algName + the default provider for that algorithm
	 */
	public Object getObject(String algName) throws FactoriesException /*throws IllegalArgumentException, SecurityException, ClassNotFoundException, 
												   NoSuchMethodException, InstantiationException, IllegalAccessException, 
												   InvocationTargetException*/{

		//no provider has been supplied. Get the provider name from the default implementation properties.
		String provider = getDefaultImplProvider(algName);
		
		return getObject(provider, algName);
	}
	
	/* 
	 * 
	 * @param algName - the required algorithm name
	 * @param params - the required parameters to the algorithm
	 * @return an object of the class that was determined by the algName + the default provider for that algorithm.
	 */
	public Object getObject(String algName, Object[] params) throws FactoriesException /*throws IllegalArgumentException, SecurityException, ClassNotFoundException,
																	NoSuchMethodException, InstantiationException, IllegalAccessException, 
																	InvocationTargetException */{

		//no provider has been supplied. Get the provider name from the default implementation properties.
		String provider = getDefaultImplProvider(algName);
		
		return getObject(provider, algName, params);
	}
	
	//nested class:
	class AlgDetails{
		public String name;					//the name  of the main algorithm
		public Vector<String> params; 		//the other algorithms to use. The params will be passed as an argument to the 
											//constructor of the main algorithm.
	}
	
	//nested class
	
	/*
	 * A utility class that aids to parse 
	 */
	class AlgorithmStringParser{
		
		private String algorithmCommand;
		private String algorithmParamsAsOneString = "";
		private String mainAlgName = "";
		
		/*
		 * AlgorithmParser the constructor
		 * @param algorithmCommand the string to work on
		 */
		public AlgorithmStringParser(String algorithmCommand) {
			
			this.algorithmCommand = algorithmCommand;
			splitToNameAndParamsAsString();
			
		}
		
		/*
		 * 
		 * Counts the number of occurrences of the parameter searchFor in base String
		 * @param searchFor the string for which we wish to count the number of occurrences for
		 * @return the number of occurrences of searchFor in base
		 */
		int occurences(String base, String searchFor){
			
			int len = searchFor.length();
			int result = 0;
			if (len > 0) {
				int start = base.indexOf(searchFor);
				while (start != -1) {
		            result++;
		            start = base.indexOf(searchFor, start+len);
		        }
		    }
			return result;
				
		}
		
		/*
		 * 
		 * Retrieves the main algorithm from the String <code>algorithmCommand</code> and generates the string
		 * <code>algorithmParamsAsOneString</code>.
		 */
		void splitToNameAndParamsAsString()
		{
			
			
			//check if this a complex algorithm command or if it contains only one algorithm
			int index = algorithmCommand.indexOf("(");
			
			if(index==-1){//simple
				algorithmParamsAsOneString = "";
				mainAlgName = algorithmCommand;
			}
			else{
				mainAlgName = (String) algorithmCommand.subSequence(0, index);
				//cut off the first left parenthesis and the last right parenthesis.
				algorithmParamsAsOneString = (String) algorithmCommand.subSequence(index+1, algorithmCommand.length()-1);
				
			}
		}
		
		/*
		 * 
		 * getAlgName :  
		 * @return the main algorithm string
		 */
		String getAlgName()
		{
			return mainAlgName;
		}
		
		
		/*
		 * 
		 * Retrieves the parameters of the algorithm from the String <code>algorithmParamsAsOneString</code>.
		 * @return a vector holding each parameter
		 */
		Vector<String> getParsedParams(){
			
			String tempParam = "";
			
			//a vector that will hold the complex parameters. A parameter can be of the form "a(b,c)" even though
			//it contains "," and is split in the params array.
			Vector<String> finalParams = new Vector<String>();
			//get the parameters into strings. The problems is that we may get more than we should. for example,
			// the string "a(b(c,d)),e"
			String [] params = algorithmParamsAsOneString.split(",");
			
			int paranthesis = 0;
			
			//go over the simple split arguments of params and form the complex params if there are any.
			for(int i=0; i< params.length ; i++){
				
				//concatenate the new param
				tempParam+= params[i];
				
				//count the number of left parenthesis minus the number of right parenthesis
				paranthesis = occurences(tempParam, "(") - occurences(tempParam, ")");
				
				//check that the accumulated string is a parameter or we should concatenate more
				if(paranthesis==0){
					//tempParam contains the full parameter add it to the vector
					if(!tempParam.isEmpty())
						finalParams.add(tempParam);
					//set as empty, we start a new parameter.
					tempParam = "";
				}
				else{
					//return the "," since it would not have been removed
					tempParam =tempParam + ",";
				}
					
			}
			
			return finalParams;
		}
		
		
	}
	
	
}
