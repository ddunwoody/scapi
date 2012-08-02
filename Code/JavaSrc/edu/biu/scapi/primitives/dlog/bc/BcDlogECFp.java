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
package edu.biu.scapi.primitives.dlog.bc;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Properties;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import edu.biu.scapi.primitives.dlog.DlogECFp;
import edu.biu.scapi.primitives.dlog.ECElement;
import edu.biu.scapi.primitives.dlog.ECFpUtility;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.groupParams.ECFpGroupParams;
import edu.biu.scapi.primitives.dlog.groupParams.GroupParams;
import edu.biu.scapi.primitives.dlog.miracl.ECFpPointMiracl;
import edu.biu.scapi.securityLevel.DDH;

/**
 * This class implements an Elliptic curve Dlog group over Fp utilizing Bouncy Castle's implementation. 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class BcDlogECFp extends BcAdapterDlogEC implements DlogECFp, DDH {
	
	private ECFpUtility util;
	
	
	/**
	 * Default constructor. Initializes this object with P-192 NIST curve.
	 */
	public BcDlogECFp() throws IOException{
		this("P-192");
	}
	
	public BcDlogECFp(String fileName, String curveName) throws IOException {
		super(fileName, curveName);
	}
	
	/**
	 * Initialize this DlogGroup with one of NIST recommended elliptic curve
	 * @param curveName - name of NIST curve to initialized
	 * @throws IOException
	 * @throws IllegalAccessException
	 */
	public BcDlogECFp(String curveName) throws IllegalArgumentException, IOException {
		this(PROPERTIES_FILES_PATH, curveName);
	}

	/**
	 * Extracts the parameters of the curve from the properties object and initialize the groupParams, 
	 * generator and the underlying curve
	 * @param ecProperties properties object contains the curve file data
	 * @param curveName the curve name as it is called in the file
	 */
	protected void doInit(Properties ecProperties, String curveName) {
		util = new ECFpUtility();
		groupParams = util.checkAndCreateInitParams(ecProperties, curveName);
		//Now that we have p, we can calculate k which is the maximum length in bytes of a string to be converted to a Group Element of this group. 
		BigInteger p = ((ECFpGroupParams)groupParams).getP();
		k = util.calcK(p);
		createUnderlyingCurveAndGenerator(groupParams);
	}
	

	/**
	 * Extracts the parameters of the curve from the groupParams, and create the corresponding BC curve and generator. 
	 * generator and the underlying curve
	 * @param params of type ECFpGroupParams
	 */
	private void createUnderlyingCurveAndGenerator(GroupParams params){
		//There is no need to check that the params passed are an instance of ECFpGroupParams since this function is only used by SCAPI.
		ECFpGroupParams fpParams = (ECFpGroupParams)params;
		// create the ECCurve
		curve = new ECCurve.Fp(fpParams.getP(), fpParams.getA(), fpParams.getB());
				
		generator = new ECFpPointBc(fpParams.getXg(), fpParams.getYg(), this);
	}
	
	
	/**
	 * @return the type of the group - ECFp
	 */
	public String getGroupType() {
		return util.getGroupType();
	}
	
	/**
	 * Checks if the given element is a member of this Dlog group
	 * @param element 
	 * @return true if the given element is member of this group; false, otherwise.
	 * @throws IllegalArgumentException
	 */
	public boolean isMember(GroupElement element) throws IllegalArgumentException{
		
		if (!(element instanceof ECFpPointBc)){
			throw new IllegalArgumentException("element type doesn't match the group type");
		}
		
		ECFpPointBc point = (ECFpPointBc) element;
		
		//infinity point is a valid member
		if (point.isInfinity()){
			return true;
		}
		
		// A point (x, y) is a member of a Dlog group with prime order q over an Elliptic Curve if it meets the following two conditions:
		// 1)	P = (x,y) is a point in the Elliptic curve, i.e (x,y) is a solution of the curve’s equation.
		// 2)	P = (x,y) is a point in the q-order group which is a sub-group of the Elliptic Curve.
		// those two checks are done in two steps:
		// 1.	Checking that the point is on the curve, performed by checkCurveMembership
		// 2.	Checking that the point is in the Dlog group,performed by checkSubGroupMembership

		boolean valid = util.checkCurveMembership((ECFpGroupParams) groupParams, point.getX(), point.getY());
		valid = valid && util.checkSubGroupMembership(this, point);
		
		return valid;
			
	}
	
	/**
	 * Creates a point over Fp field.
	 * 
	 * @return the created point
	 */
	public ECElement generateElement(BigInteger x, BigInteger y) throws IllegalArgumentException{
		//Creates element with the given values.
		ECFpPointBc point =  new ECFpPointBc(x, y, this);
		
		//if the element was created, it is a point on the curve.
		//checks if the point is in the sub-group, too.
		boolean valid = util.checkSubGroupMembership(this, point);
		
		//if the point is not in the sub-group, throw exception.
		if (valid == false){
			throw new IllegalArgumentException("Could not generate the element. The given (x, y) is not a point in this Dlog group");
		}
		
		return point;
	}
	
	/**
	 * Creates ECPoint.Fp with the given parameters
	 */
	protected GroupElement createPoint(ECPoint result) {
		return new ECFpPointBc(result);
	}
	
	/**
	 * Check if the element is valid to this elliptic curve group
	 */
	protected boolean checkInstance(GroupElement element) {
		if (element instanceof ECFpPointBc) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Creates ECPoint.Fp with infinity values
	 */
	public ECElement getInfinity() {
		ECPoint infinity = curve.getInfinity();
		return new ECFpPointBc(infinity);
	}
	
	/**
	 * Converts a byte array to an ECFpPointBc.
	 * @param binaryString the byte array to convert
	 * @throws IndexOutOfBoundsException if the length of the binary array to encode is longer than k
	 * @return the created group Element
	 */
	public GroupElement encodeByteArrayToGroupElement(byte[] binaryString) {
		ECFpUtility.FpPoint fpPoint = util.findPointRepresentedByByteArray((ECFpGroupParams) groupParams, binaryString, k); 
		ECElement element = generateElement(fpPoint.getX(), fpPoint.getY());
		return element;
	}
	
	/**
	 * Convert a ECFpPointBc to a byte array.
	 * @param groupElement the element to convert
	 * @return the created byte array
	 */
	public byte[] decodeGroupElementToByteArray(GroupElement groupElement) {
		if (!(groupElement instanceof ECFpPointBc)) {
			throw new IllegalArgumentException("element type doesn't match the group type");
		}
		ECFpPointBc point = (ECFpPointBc) groupElement;
		byte[] b1 = util.getKLeastSignBytes(point.getX(), k +1);
		byte[] b2 = new byte[b1.length -1];
		System.arraycopy(b1, 1, b2, 0, b2.length);
		return b2;
	}

	/**
	 * This function maps a group element of this dlog group to a byte array.<p>
	 * This function does not have an inverse function, that is, it is not possible to re-construct the original group element from the resulting byte array.<p>
	 * Moreover, the implementation of this function is such that for a given group element (point in the curve),<p>
	 * the result of applying this function (mapAnyGroupElementToByteArray) and the result of applying decodeGroupElementToByteArray are not equal.    
	 * @return a byte array representation of the given group element
	 */
	public byte[] mapAnyGroupElementToByteArray(GroupElement groupElement) {
		//This function simply returns an array which is the result of concatenating 
		//the byte array representation of x with the byte array representation of y.
		if (!(groupElement instanceof ECFpPointBc)) {
			throw new IllegalArgumentException("element type doesn't match the group type");
		}
		ECFpPointBc point = (ECFpPointBc) groupElement;
		//The actual work is implemented in ECFpUtility since it is independent of the underlying library (BC, Miracl, or other)
		//If we ever decide to change the implementation there will only one place to change it.
		return util.mapAnyGroupElementToByteArray(point.getX(), point.getY());
	}


	
}
