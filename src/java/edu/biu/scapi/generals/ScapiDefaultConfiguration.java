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
package edu.biu.scapi.generals;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.util.logging.Level;

/**
 * This class manage SCAPI's default values. The default values are read from a configuration file. 
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class ScapiDefaultConfiguration {

	private static final ScapiDefaultConfiguration instance = new ScapiDefaultConfiguration();
	private Properties ecProperties = null;
	private static final String PROPERTIES_FILES_PATH = "/propertiesFiles/";
	
	private ScapiDefaultConfiguration(){
		ecProperties = new Properties();

		//Instead of loading the plain file, which only works from outside a jar file, we load it as a resource 
		//that can also work from within a jar file. The path from which we load the properties file from is from now under bin\propertiesFiles.
		InputStream in=  (InputStream) getClass().getResourceAsStream(PROPERTIES_FILES_PATH + "SCAPIDefaultConfig.properties");
		try {
			ecProperties.load(in);
		} catch (IOException e) {
			Logging.getLogger().log(Level.SEVERE, "A problem was found when trying to open SCAPIDefaultConfig.properties file: " + e.getMessage());
		}	
	}

	public static ScapiDefaultConfiguration getInstance() {
		return instance;
	}
	
	public String getProperty(String key){
		return ecProperties.getProperty(key);
	}
	

	
}
