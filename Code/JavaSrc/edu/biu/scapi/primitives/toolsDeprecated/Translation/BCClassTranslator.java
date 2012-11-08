/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2012 - SCAPI (http://crypto.biu.ac.il/scapi)
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
