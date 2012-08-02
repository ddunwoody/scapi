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
package edu.biu.scapi.tools.Translation;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.Digest;


/** 
 * @author LabTest
 */
public class BCClassTranslator {
	private Properties classes;
	private final static BCClassTranslator classTranslator = new BCClassTranslator();//singleton

	/**
	 * Empty constructor should be private since this class is singleton and we want to prevent user creation
	 * of this class
	 */
	private BCClassTranslator(){
		
		//load the classes from the predefined file.
		loadClassesFromFile();
	};
	
	/** 
	 * @return
	 */
	public static BCClassTranslator getInstance() {
		
		return classTranslator;
	}

	/** 
	 * Loads the BC classes from file "BCClasses.properties" and places them in the classes attribute
	 */
	private void loadClassesFromFile() {
		
		//instantiate the classes properties
		classes = new Properties();
        
        /*
        //the class names file should look something like this:
        
        "# Bouncy Castle 
        DES = DESEngine
        RSA = RSAEngine " */
        try {
        	
        	//load the classes file
        	classes.load(new FileInputStream("BCClasses.properties"));
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
        
        
	}

	/** 
	 * @param name - the name of the BlockCipher to load
	 * @return A BlockCipher instance of the class that is related to the parameter name
	 * @throws ClassNotFoundException 
	 * @throws IllegalAccessException 
	 * @throws InstantiationException 
	 */
	public BlockCipher loadBCBlockCipher(String name) throws InstantiationException, IllegalAccessException, ClassNotFoundException {
		
		return (BlockCipher)loadClass(name);
	}

	/** 
	 * @param name - the name of the AsymmetricBlockCipher to load
	 * @return An AsymmetricBlockCipher instance of the class that is related to the parameter name
	 * @throws ClassNotFoundException 
	 * @throws IllegalAccessException 
	 * @throws InstantiationException 
	 */
	public AsymmetricBlockCipher loadBCAsymetricBlockCipher(String name) throws InstantiationException, IllegalAccessException, ClassNotFoundException {
		
		return (AsymmetricBlockCipher)loadClass(name);
	}

	/** 
	 * 
	 * @param name - the name of the Digest to load
	 * @return A digest instance of the class that is related to the parameter name
	 * @throws ClassNotFoundException 
	 * @throws IllegalAccessException 
	 * @throws InstantiationException 
	 */
	public Digest loadBCDigest(String name) throws InstantiationException, IllegalAccessException, ClassNotFoundException {

		return (Digest)loadClass(name);
	}

	/** 

	 * @param name - the name of the class to load
	 * @return
	 */
	public StreamCipher loadBCStreamCipher(String name) {
		// begin-user-code
		// TODO Auto-generated method stub
		return null;
		// end-user-code
	}
	
	private Object loadClass(String name) throws InstantiationException, IllegalAccessException, ClassNotFoundException{
		
		Class cls;
		
		//get our class loader
		ClassLoader classLoader = getClass().getClassLoader();
		
		//retrieve the name of the class from the classes properties.
		String className = classes.getProperty(name);

		//use the ClassLoader to load the class by its name taken from the properties and put in attribute cls
		cls = classLoader.loadClass(className);
		//create a new object using the class. This will call the empty constructor of the related class
		Object obj = cls.newInstance(); 

		return obj; 


	}
}
