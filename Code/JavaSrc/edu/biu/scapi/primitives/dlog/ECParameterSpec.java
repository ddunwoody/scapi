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
package edu.biu.scapi.primitives.dlog;

import java.security.spec.AlgorithmParameterSpec;

public class ECParameterSpec implements AlgorithmParameterSpec {
	private String fileName = System.getProperty("java.class.path").toString().split(";")[0]+"\\propertiesFiles\\NISTEC.properties";;
	private String curveName;
	
	/**
	 * Constructor that gets the file name that contains the curves properties and the required curve name
	 * If the user wants to use one of NIST's curves, he can pass the path of our NIST's curves file 
	 * or call the other constructor that gets only the curve name. 
	 * @param fileName that contains the curves properties
	 * @param curveName required curve name
	 */
	public ECParameterSpec(String fileName, String curveName){
		this.fileName = fileName;
		this.curveName = curveName;
	}
	
	/**
	 * Constructor that gets the required curve name. 
	 * This constructor is for NIST's curves and the curve is taken from our properties file that contains NIST's curves.
	 * If the user wants to use a curve that is not one of NIST's curves, he can pass the path of his curves properties file to the other constructor. 
	 * @param curveName required NIST's curve name
	 */
	public ECParameterSpec(String curveName){
		this.curveName = curveName;
	}
	
	/**
	 *
	 * @return the file contains the required curve
	 */
	public String getFileName(){
		return fileName;
	}
	
	/**
	 * 
	 * @return the name of the required curve
	 */
	public String getCurveName(){
		return curveName;
	}
}
