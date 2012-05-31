package edu.biu.scapi.primitives.dlog.miracl;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Properties;

import org.bouncycastle.util.encoders.Hex;

import edu.biu.scapi.primitives.dlog.DlogECFp;
import edu.biu.scapi.primitives.dlog.ECElement;
import edu.biu.scapi.primitives.dlog.ECFpUtility;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.groupParams.ECFpGroupParams;
import edu.biu.scapi.securityLevel.DDH;

/**
/**This class implements an Elliptic curve Dlog group over Zp utilizing Miracl's implementation.<p>
 * It uses JNI technology to call Miracl's native code.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 */
public class MiraclDlogECFp extends MiraclAdapterDlogEC implements DlogECFp, DDH{

	private native void initFpCurve(long mip, byte[] p, byte[] a,byte[] b);
	private native long multiplyFpPoints(long mip, long p1, long p2);
	private native long simultaneousMultiplyFp(long mip, long[] points, byte[][] exponents);
	private native long exponentiateFpPoint(long mip, long p, byte[] exponent);
	private native long invertFpPoint(long mip, long p);
	private native boolean validateFpGenerator(long mip, long generator, byte[] x, byte[] y);
	private native boolean isFpMember(long mip, long point);
	private native long createInfinityFpPoint(long mip);
	private native long createECFpObject(long mip, byte[] p, byte[] a, byte[] b);
	private native long exponentiateFpWithPreComputed(long mip, long dlogGroup, long base, byte[] size, int window, int maxBits);

	private long nativeDlog = 0;
	private ECFpUtility util = new ECFpUtility();
	/**
	 * Default constructor. Initializes this object with P-192 NIST curve.
	 */
	public MiraclDlogECFp() throws IOException {
		this("P-192");
	}

	public MiraclDlogECFp(String fileName, String curveName) throws IOException {
		super(fileName, curveName);
	}

	public MiraclDlogECFp(String curveName) throws IllegalArgumentException, IOException{
		

		Properties ecProperties;

		ecProperties = getProperties(PROPERTIES_FILES_PATH); //get properties object containing the curve data

		// checks that the curveName is in the file
		if (!ecProperties.containsKey(curveName)) {
			throw new IllegalArgumentException("no such NIST elliptic curve");
		}
		this.curveName = curveName;
		// check that the given curve is in the field that matches the group
		if (!curveName.startsWith("P-")) {
			throw new IllegalArgumentException("curveName is not a curve over Fp field and doesn't match the DlogGroup type"); 
		}
		doInit(ecProperties, curveName);  // set the data and initialize the curve
		
			
	}

	/**
	 * Extracts the parameters of the curve from the properties object and initialize the groupParams, 
	 * generator and the underlying curve
	 * @param ecProperties - properties object contains the curve file data
	 * @param curveName - the curve name as it called in the file
	 */
	protected void doInit(Properties ecProperties, String curveName) {
		// get the nist parameters
		BigInteger p = new BigInteger(ecProperties.getProperty(curveName));
		BigInteger a = new BigInteger(ecProperties.getProperty(curveName + "a"));
		BigInteger b = new BigInteger(1,Hex.decode(ecProperties.getProperty(curveName+"b")));
		BigInteger x = new BigInteger(1,Hex.decode(ecProperties.getProperty(curveName+"x")));
		BigInteger y = new BigInteger(1,Hex.decode(ecProperties.getProperty(curveName+"y")));
		BigInteger q = new BigInteger(ecProperties.getProperty(curveName + "r"));
		BigInteger h = new BigInteger(ecProperties.getProperty(curveName + "h"));

		// create the GroupParams
		groupParams = new ECFpGroupParams(q, x, y, p, a, b, h);

		// create the curve
		initFpCurve(getMip(), p.toByteArray(), a.mod(p).toByteArray(), b.toByteArray());

		// create the generator
		generator = new ECFpPointMiracl(x, y, this);
	}

	/**
	 * @return the type of the group - ECFp
	 */
	public String getGroupType() {
		return "elliptic curve over Fp";
	}

	/**
	 * Calculate the inverse of the given GroupElement
	 * @param groupElement to inverse
	 * @return the inverse element of the given GroupElement
	 * @throws IllegalArgumentException
	 */
	public GroupElement getInverse(GroupElement groupElement) throws IllegalArgumentException{
		
		//if the GroupElement doesn't match the DlogGroup, throw exception
		if (!(groupElement instanceof ECFpPointMiracl)){
			throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
		}

		// the inverse of infinity point is infinity
		if (((ECFpPointMiracl) groupElement).isInfinity()) {
			return groupElement;
		}

		long point = ((ECFpPointMiracl) groupElement).getPoint();
		// call to native inverse function
		long result = invertFpPoint(mip, point);
		// build a ECFpPointMiracl element from the result value
		return new ECFpPointMiracl(result, this);

	}

	/**
	 * Multiply two GroupElements
	 * @param groupElement1
	 * @param groupElement2
	 * @return the multiplication result
	 * @throws IllegalArgumentException
	 */
	public GroupElement multiplyGroupElements(GroupElement groupElement1,
						GroupElement groupElement2) throws IllegalArgumentException {

		// if the GroupElements don't match the DlogGroup, throw exception
		if (!(groupElement1 instanceof ECFpPointMiracl)) {
			throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
		}
		if (!(groupElement2 instanceof ECFpPointMiracl)){
			throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
		}

		//if one of the points is the infinity point, the second one is the multiplication result
		if (((ECFpPointMiracl) groupElement1).isInfinity()) {
			return groupElement2;
		}
		if (((ECFpPointMiracl) groupElement2).isInfinity()) {
			return groupElement1;
		}

		long point1 = ((ECFpPointMiracl) groupElement1).getPoint();
		long point2 = ((ECFpPointMiracl) groupElement2).getPoint();

		// call to native multiply function
		long result = multiplyFpPoints(mip, point1, point2);
		// build a ECFpPointMiracl element from the result value
		return new ECFpPointMiracl(result, this);

	}

	/**
	 * Calculate the exponentiate of the given GroupElement
	 * @param exponent
	 * @param base
	 * @return the result of the exponentiation
	 * @throws IllegalArgumentException
	 */
	public GroupElement exponentiate(GroupElement base, BigInteger exponent)
									throws IllegalArgumentException {

		// if the GroupElements don't match the DlogGroup, throw exception
		if (!(base instanceof ECFpPointMiracl)) {
			throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
		}

		// infinity remains the same after any exponentiate
		if (((ECFpPointMiracl) base).isInfinity()) {
			return base;
		}

		long point = ((ECFpPointMiracl) base).getPoint();
		// call to native exponentiate function
		long result = exponentiateFpPoint(mip, point, exponent.toByteArray());
		// build a ECFpPointMiracl element from the result value
		return new ECFpPointMiracl(result, this);

	}

	/**
	 * Computes the product of several exponentiations with distinct bases 
	 * and distinct exponents. 
	 * Instead of computing each part separately, an optimization is used to 
	 * compute it simultaneously. 
	 * @param groupElements
	 * @param exponentiations
	 * @return the exponentiation result
	 */
	@Override
	public GroupElement simultaneousMultipleExponentiations(GroupElement[] groupElements, 
			BigInteger[] exponentiations) {
		
		int len = groupElements.length;
		
		//Our test results show that for elliptic curve over Fp and n<25 the naive algorithm gives the best performances
		if (len < 25) {
			return computeNaive(groupElements, exponentiations);
		}

		long[] nativePoints = new long[len];
		byte[][] exponents = new byte[len][];
		for (int i = 0; i < len; i++) {
			// if the GroupElements don't match the DlogGroup, throw exception
			if (!(groupElements[i] instanceof ECFpPointMiracl)) {
				throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
			}
			nativePoints[i] = ((ECFpPointMiracl) groupElements[i]).getPoint();
			exponents[i] = exponentiations[i].toByteArray();
		}

		// call to native exponentiate function
		long result = simultaneousMultiplyFp(mip, nativePoints, exponents);
		// build a ECF2mPointMiracl element from the result value
		return new ECFpPointMiracl(result, this);
	}

	@Override
	public GroupElement exponentiateWithPreComputedValues
			(GroupElement groupElement, BigInteger exponent){

		//override of the function exponentiateWithPreComputedValues that uses the same algorithm as the ABS but in native.
		//Results showed that the naive algorithm is faster so we dicide not to use this algorithm but the naive

		// if the GroupElements don't match the DlogGroup, throw exception
		if (!(groupElement instanceof ECFpPointMiracl)) {
			throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
		}

		ECFpPointMiracl base = (ECFpPointMiracl) groupElement;

		// infinity remains the same after any exponentiate
		if (base.isInfinity()) {
			return base;
		}

		if (nativeDlog == 0) {
			ECFpGroupParams params = (ECFpGroupParams) getGroupParams();
			nativeDlog = createECFpObject(mip, params.getP().toByteArray(), params.getA().mod(params.getP()).toByteArray(), params.getB().toByteArray());
		}
		
		//call to native exponentiate function
		long result = exponentiateFpWithPreComputed(mip, nativeDlog, base.getPoint(), exponent.toByteArray(), getWindow(), getOrder().bitLength());

		// build a ECFpPointMiracl element from the result value
		return new ECFpPointMiracl(result, this);
	}

	/**
	 * Create a point in the Fp field with the given parameters
	 * 
	 * @return the created point
	 */
	public ECElement generateElement(BigInteger x, BigInteger y) throws IllegalArgumentException{
		//Creates element with the given values.
		ECFpPointMiracl point =  new ECFpPointMiracl(x, y, this);
		
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
	 * Check if the given element is member of that Dlog group
	 * @param element - 
	 * @return true if the given element is member of that group. false, otherwise.
	 * @throws IllegalArgumentException
	 */
	public boolean isMember(GroupElement element) {

		// checks that the element is the correct object
		if (!(element instanceof ECFpPointMiracl)) {
			throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
		}

		ECFpPointMiracl point = (ECFpPointMiracl) element;
		// infinity point is a valid member
		if (point.isInfinity()) {
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

	public ECElement getInfinity() {
		long infinity = createInfinityFpPoint(mip);
		return new ECFpPointMiracl(infinity, this);
	}

	// upload MIRACL library
	static {
		System.loadLibrary("MiraclJavaInterface");
	}

	/**
	 * Converts a byte array to a ECFpPointMiracl.
	 * @param binaryString the byte array to convert
	 * @return the created group Element
	 */
	public GroupElement convertByteArrayToGroupElement(byte[] binaryString) {
		//currently we don't support this conversion. 
		//will be implemented in the future.
		return null;
	}

	/**
	 * Convert a ECFpPointMiracl to a byte array.
	 * @param groupElement the element to convert
	 * @return the created byte array
	 */
	public byte[] convertGroupElementToByteArray(GroupElement groupElement) {
		if (!(groupElement instanceof ECFpPointMiracl)) {
			throw new IllegalArgumentException("element type doesn't match the group type");
		}
		//currently we don't support this conversion. 
		//will be implemented in the future.
		return null;
	}

	// upload MIRACL library
	static {
		System.loadLibrary("MiraclJavaInterface");
	}
}
