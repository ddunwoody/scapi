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


package edu.biu.scapi.primitives.dlog;

import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import java.util.Properties;


/**
 * This class manages the creation of NIST recommended elliptic curves.
 * We have a properties file which contains the parameters for the curves. 
 * This class uploads the file once, and constructs a properties object from it.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public abstract class DlogGroupEC extends DlogGroupAbs implements DlogEllipticCurve{

	private  Properties nistProperties; // properties object to hold nist parameters
	protected static final String NISTEC_PROPERTIES_FILE =  "/propertiesFiles/NISTEC.properties";
	protected String curveName;
	protected String fileName;
	
	protected DlogGroupEC(){};
	
	/**
	 * Constructor that initializes this DlogGroup with a curve that is not necessarily one of NIST recommended elliptic curves.
	 * @param fileName - name of the elliptic curves file. This file has to comply with 
	 * @param curveName - name of curve to initialized
	 * @throws IOException 
	 */
	protected DlogGroupEC(String fileName, String curveName) throws IOException{
		this(fileName, curveName, new SecureRandom());
		
	}
	
	/**
	 * Constructor that initializes this DlogGroup with a curve that is not necessarily one of NIST recommended elliptic curves.
	 * @param fileName - name of the elliptic curves file. This file has to comply with 
	 * @param curveName - name of curve to initialized
	 * @throws IOException 
	 */
	protected DlogGroupEC(String fileName, String curveName, SecureRandom random) throws IOException{
		Properties ecProperties;
		
		ecProperties = getProperties(fileName); //get properties object containing the curve data
		//PROPERTIES_FILES_PATH = fileName;
		//checks that the curveName is in the file 
		if(!ecProperties.containsKey(curveName)) { 
			throw new IllegalArgumentException("no such elliptic curve in the given file");
		}
		this.curveName = curveName;
		this.fileName = fileName;
			
		this.random = random;
		
		doInit(ecProperties, curveName); // set the data and initialize the curve
		
	}

	protected abstract void doInit(Properties ecProperties, String curveName);
	
			

	protected Properties getProperties(String fileName) throws IOException{
		Properties ecProperties = null;
		
		//If we had already open the NISTEC file then do not open it again, just return it.
		if(fileName.equals(NISTEC_PROPERTIES_FILE) && nistProperties!=null){
			return nistProperties;
		}
	
		ecProperties = new Properties();
		//Load the elliptic curves file
		//Instead of loading the plain file, which only works from outside a jar file, we load it as a resource 
		//that can also work from within a jar file. The path from which we load the properties file from is from now under bin\propertiesFiles.
		InputStream in=  (InputStream) getClass().getResourceAsStream(fileName);
		ecProperties.load(in);
		 
		//Set the member variable nistProperties to the recently loaded ecProperties file, so that next time
		//the NIST file has to be read, the already loaded file will be returned. (See above). 
		if(fileName.equals(NISTEC_PROPERTIES_FILE)){
			nistProperties = ecProperties;
		}

		return ecProperties;
	}
	
	public String getCurveName(){
		return curveName;
	}
	
	public String getFileName(){
		return fileName;
	}
	
	/**
	 * Checks parameters of this group to see if they conform to the type this group is supposed to be.<p> 
	 * Parameters are uploaded from a configuration file upon construction of concrete instance of an Elliptic Curve Dlog group.
	 * By default, SCAPI uploads a file with NIST recommended curves. In this case we assume the parameters are always correct.
	 * It is also possible to upload a user-defined configuration file (with format specified in the "Elliptic Curves Parameters File Format" section of the FirstLevelSDK_SDD.docx file). In this case,
	 * it is the user's responsibility to check the validity of the parameters.
	 * In both ways, the parameters we set should be correct. Therefore, currently the function validateGroup does not perform any validity check and always returns true.
	 * In the future we may add the validity checks.
	 * @return true.
	 */
	public boolean validateGroup(){
		return true;
	}

	
	/**
	 * Checks if the element set as the generator is indeed the generator of this group.
	 * The generator is set upon construction of this group. <p>
	 * For Elliptic curves there are two ways to set the generator. One way is to load it from NIST file, so the generator is correct. 
	 * The second way is to get the generator values from the user in the init function. In that way, it is the user's responsibility to check the validity of the parameters.
	 * In both ways, the generator we set must be correct. However, currently the function isGenerator does not operate the validity check and always returns true.
	 * Maybe in the future we will add the validity checks.
	 * @return <code>true</code> is the generator is valid;<p>
	 * 		   <code>false</code> otherwise.
	 * 
	 */
	public boolean isGenerator(){
		return true;
	}
	
	/**
	 * For Elliptic Curves, the identity is equivalent to the infinity.
	 * @return the identity of this Dlog group
	 */
	public GroupElement getIdentity(){
		return getInfinity();
	}
		
	/**
	 * @deprecated As of SCAPI-V2_0_0 use generateElment(boolean bCheckMembership, BigInteger...values)
	 */
	@Deprecated public GroupElement generateElement(boolean bCheckMembership, GroupElementSendableData data) {
		if (!(data instanceof ECElementSendableData))
			throw new IllegalArgumentException("data type doesn't match the group type");
		return generateElement(bCheckMembership, ((ECElementSendableData)data).getX(), ((ECElementSendableData)data).getY());
	}
	/**
	 * @see edu.biu.scapi.primitives.dlog.DlogGroup#reconstructElement(boolean, edu.biu.scapi.primitives.dlog.GroupElementSendableData)
	 */
	@Override
	public GroupElement reconstructElement(boolean bCheckMembership, GroupElementSendableData data) {
		if (!(data instanceof ECElementSendableData))
			throw new IllegalArgumentException("data type doesn't match the group type");
		return generateElement(bCheckMembership, ((ECElementSendableData)data).getX(), ((ECElementSendableData)data).getY());
	}
}
