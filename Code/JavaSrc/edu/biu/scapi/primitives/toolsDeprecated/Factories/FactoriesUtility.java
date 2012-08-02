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
 * The FactoriesUtility class as its name indicates is a utility class used by all the factories. 
 * The actual creation of the object is done with this class in the public function getObject. 
 * All the factories call this method and cast the created object to the actual type they need to return. 
 */
package edu.biu.scapi.tools.Factories;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.Properties;
import java.util.Vector;
import java.util.regex.PatternSyntaxException;

/** 
 * @author LabTest
 */
public class FactoriesUtility {
	private Properties defaultProviderMap;
	private Properties algsInType;

	
	/*public static void main(String[] args){
		
		FactoriesUtility.AlgorithmStringParser parser = new FactoriesUtility.AlgorithmStringParser("a(x(b,c),d,e(f))");
		String name = parser.getAlgName();
		Vector<String> vec = parser.getParsedParams();
	}*/
	
	/** 
	 * FactoriesUtility - load the files to the properties atributes.
	 * @param defaultProviderFileName - the file name from which to load the default provider properties from. 
	 * 									*Note that this can be null. for example the BCFactory does not need to pass
	 * 									 default provider for each implementation. 
	 * @param algsInTypeFileName - the file name from which to load the algorithms in type properties from
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
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		
	}
	
	/** 
	 * @param algNames
	 * @return
	 */
	private AlgDetails parseAlgNames(String algNames) {

		AlgDetails algDetails = new AlgDetails();
		AlgorithmStringParser parser = new AlgorithmStringParser(algNames);
		algDetails.name = parser.getAlgName();
		algDetails.params = parser.getParsedParams();
		
		return algDetails;
		
	}

	/** 
	 * @param algName - the algorithm for which to check validity for
	 * @return : true - if the algorithm exists in the defaultProviderMap, else false.
	 */
	private boolean checkValidity(String algName) {

		return defaultProviderMap.contains(algName);
	}

	/** 
	 * @param provider
	 * @param algName
	 * @return
	 */
	private String prepareKey(String provider, String algName) {
		
		return provider+algName;

	}

	/**
	 * @throws IOException 
	 * @throws FileNotFoundException  
	 */
	private void loadAlgsInType(String algsInTypeFileName) throws FileNotFoundException, IOException {
		
		//instantiate the default provider properties
		algsInType = new Properties();
        
        /*
        //the algorithm classes file should look something like this:
        
        "# Bouncy Castle 
        BcAES = BcAES
        ScAES = AES " */
        
        	
        //load the algsInTypeFileName file
		algsInType.load(new FileInputStream(algsInTypeFileName));
	}

	/**
	 * @throws IOException 
	 * @throws FileNotFoundException  
	 */
	private void loadDefaultProvider(String defaultProviderFileName) throws FileNotFoundException, IOException {
		
		//instantiate the default provider properties
		defaultProviderMap = new Properties();
        
        /*
        //the default provider file should look something like this:
        
        "# Bouncy Castle 
        DES = BC
        AES = Sc " */
        
        	
        //load the defaultProviderFileName file
		defaultProviderMap.load(new FileInputStream(defaultProviderFileName));
		
		
	}

	/** 
	 * getDefaultImplProvider : This function may return different libraries for different objects. 
	 * For example, it may return "Crypto++" when requesting a Rabin trapdoor permutation and "BC" when requesting an AES implementation. 
	 * The decision on which implementation to return will be based on the available implementations, 
	 * on performance and other relevant reasons. 
	 * 
	 * @param algName
	 * @return : the default provider for the algorithm specified with the key algName.
	 */
	public String getDefaultImplProvider(String algName) {
		
		return defaultProviderMap.getProperty(algName);
	}

	/** 
	 * @param provider - the required provider name
	 * @param algName - the required algorithm name
	 * @return an object of the class that was determined by the algName + provider
	 */
	public Object getObject(String provider, String algName) {
		
		//get the parsed algorithm details
		AlgDetails algDetails = parseAlgNames(algName);
		//check the validity of the request. Meaning, the requested algorithm does exist. 
		boolean valid = checkValidity(algDetails.name);
		if(!valid)
			return null;
		
		//get the key as written in the property file
		String keyToMap = prepareKey(provider, algName);
		
		//get the related algorithm class name
		String className = algsInType.getProperty(keyToMap);
		
		Class algClass  = null;//will hold an Object of type Class representing our alg class
		Object newObj = null;//will the final create algorithm object
		try {
			//get the class object thru the name of the algorithm class
			algClass = Class.forName(className);
	
			//fill the classes of strings with the length of the vector. This will ensure that we get the right/relevant
			//constructor
			int size = algDetails.params.size();
			Class[] classes = new Class[size]; 
			
			//fill the array with String classes
			for(int i=0;i<size;i++){
				classes[i] = String.class;
			}
			
			//get the constructor that has classes.length number of arguments of string type  
			Constructor constructor = algClass.getConstructor(classes);
			
			
			//prepare parameters for constructor:
			//get the vector of parameters from the algorithm details object.
			//create an instance of type algClass by calling the obtained constructor:
			 newObj = constructor.newInstance(algDetails.params);
			 
		} catch (SecurityException e) {
			e.printStackTrace();
		} catch (NoSuchMethodException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
		} catch (InstantiationException e) {
			e.printStackTrace();
		} catch (IllegalAccessException e) {
			e.printStackTrace();
		} catch (InvocationTargetException e) {
			e.printStackTrace();
		}
			return  newObj;
		
	}

	

	/** 
	 * 
	 * @param algName - the required algorithm name
	 * @return an object of the class that was determined by the algName + the default provider for that algorithm.
	 */
	public Object getObject(String algName) {

		//no provider has been supplied. Get the provider name from the default implementation properties.
		String provider = getDefaultImplProvider(algName);
		
		return getObject(provider, algName);
	}
	
	//nested class:
	class AlgDetails{
		public String name;					//the name  of the main algorithm
		public Vector<String> params; 			//the other algorithms to use. The params will be passed as an argument to the 
											//constructor of the main algorithm.
	}
	
	//nested class
	class AlgorithmStringParser{
		
		String algorithmCommand;
		String algorithmParamsAsOneString = "";
		String mainAlgName = "";
		
		/**
		 * AlgorithmParser - the constructor
		 * @param algorithmCommand - the string to work on
		 */
		public AlgorithmStringParser(String algorithmCommand) {
			
			this.algorithmCommand = algorithmCommand;
			splitToNameAndParamsAsString();
			
		}
		
		/**
		 * 
		 * occurrences - counts the number of occurrences of the parameter searchFor in base String
		 * @param searchFor - the string for which we wish to count the number of occurrences for
		 * @return - the number of occurrences of searchFor in base
		 */
		int occurances(String base, String searchFor){
			
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
		
		/**
		 * 
		 * splitToNameAndParamsAsString - retrieves the main algorithm from the String algorithmCommand and generates the string
		 * 								  algorithmParamsAsOneString.
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
		
		/**
		 * 
		 * getAlgName - 
		 * @return the main algorithm string
		 */
		String getAlgName()
		{
			return mainAlgName;
		}
		/**
		 * 
		 * getParsedParams - retrieves the paramters of the algorithm from the String algorithmParamsAsOneString
		 * @return - a vector holding each parameter
		 */
		Vector<String> getParsedParams(){
			
			String tempParam = new String();
			
			//a vector that will hold the complex paramters. A parameter can be of the form "a(b,c)" even though
			//it contains "," and is split in the params array.
			Vector<String> finalParams = new Vector<String>();
			//get the parameters into strings. The problems is that we may get more than we should. for example,
			// the string "a(b(c,d)),e"
			String [] params = algorithmParamsAsOneString.split(",");
			
			int paranthesis = 0;
			
			//go over the simple splitted arguments of params and form the complex params if there are any.
			for(int i=0; i< params.length ; i++){
				
				//concatenate the new param
				tempParam+= params[i];
				
				//count the number of left parenthesis minus the number of right paranthesis
				paranthesis = occurances(tempParam, "(") - occurances(tempParam, ")");
				
				//check that the accumulated string is a paramter or we should concatenate more
				if(paranthesis==0){
					//tempParam contains the full parameter add it to the vector
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
