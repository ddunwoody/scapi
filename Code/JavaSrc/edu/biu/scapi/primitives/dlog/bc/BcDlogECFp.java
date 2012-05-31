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
import edu.biu.scapi.securityLevel.DDH;

/**
 * This class implements an Elliptic curve Dlog group over Fp utilizing Bouncy Castle's implementation. 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class BcDlogECFp extends BcAdapterDlogEC implements DlogECFp, DDH {
	
	private ECFpUtility util = new ECFpUtility();
	
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
		
		Properties ecProperties = getProperties(PROPERTIES_FILES_PATH); // get properties object containing the curve data
	
		// checks that the curveName is in the file
		if (!ecProperties.containsKey(curveName)) {
			throw new IllegalArgumentException("no such NIST elliptic curve");
		}
		this.curveName = curveName;
		// check that the given curve is in the field that matches the group
		if (!curveName.startsWith("P-")) {
			throw new IllegalArgumentException( "curveName is not a curve over Fp field and doesn't match the DlogGroup type");
		}

		doInit(ecProperties, curveName); // set the data and initialize the curve
	}

	/**
	 * Extracts the parameters of the curve from the properties object and initialize the groupParams, 
	 * generator and the underlying curve
	 * @param ecProperties properties object contains the curve file data
	 * @param curveName the curve name as it called in the file
	 */
	protected void doInit(Properties ecProperties, String curveName) {

		// get the curve parameters
		BigInteger p = new BigInteger(ecProperties.getProperty(curveName));
		BigInteger a = new BigInteger(ecProperties.getProperty(curveName + "a"));
		BigInteger b = new BigInteger(1, Hex.decode(ecProperties.getProperty(curveName + "b")));
		BigInteger x = new BigInteger(1, Hex.decode(ecProperties.getProperty(curveName + "x")));
		BigInteger y = new BigInteger(1, Hex.decode(ecProperties.getProperty(curveName + "y")));
		BigInteger q = new BigInteger(ecProperties.getProperty(curveName + "r"));
		BigInteger h = new BigInteger(ecProperties.getProperty(curveName + "h"));
		
		// create the GroupParams
		groupParams = new ECFpGroupParams(q, x, y, p, a, b, h);
		
		// create the ECCurve
		curve = new ECCurve.Fp(p, a, b);
		
		generator = new ECFpPointBc(x, y, this);
	}
	
	/**
	 * @return the type of the group - ECFp
	 */
	public String getGroupType() {
		return "elliptic curve over Fp";
	}
	
	/*
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
		// those two checks is done in two steps:
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
	 * 	
	 * @param binaryString the byte array to convert
	 * @return the created group Element
	 */
	public GroupElement convertByteArrayToGroupElement(byte[] binaryString) {
		
		//currently we don't support this conversion. 
		//will be implemented in the future.
		return null;
	}
	
	/**
	 * Convert a ECFpPointBc to a byte array.
	 * @param groupElement the element to convert
	 * @return the created byte array
	 */
	public byte[] convertGroupElementToByteArray(GroupElement groupElement) {
		if (!(groupElement instanceof ECFpPointBc)) {
			throw new IllegalArgumentException("element type doesn't match the group type");
		}
		//currently we don't support this conversion. 
		//will be implemented in the future.
		return null;
	}
	
}
