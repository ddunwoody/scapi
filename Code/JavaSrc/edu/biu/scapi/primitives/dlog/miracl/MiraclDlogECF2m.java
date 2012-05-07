package edu.biu.scapi.primitives.dlog.miracl;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Properties;

import org.bouncycastle.util.encoders.Hex;

import edu.biu.scapi.primitives.dlog.DlogECF2m;
import edu.biu.scapi.primitives.dlog.ECElement;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mGroupParams;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mKoblitz;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mPentanomialBasis;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mTrinomialBasis;
import edu.biu.scapi.securityLevel.DDH;

/**This class implements a Dlog group over F2m utilizing Miracl++'s implementation.<p>
 * It uses JNI technology to call Miracl's native code.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 */
public class MiraclDlogECF2m extends MiraclAdapterDlogEC implements DlogECF2m, DDH{

	private native void initF2mCurve(long mip, int m, int k1, int k2, int k3, byte[] a, byte[] b);
	private native long multiplyF2mPoints(long mip, long p1, long p2);
	private native long simultaneousMultiplyF2m(long mip, long[] points, byte[][] exponents);
	private native long exponentiateF2mPoint(long mip, long p, byte[] exponent);
	private native long invertF2mPoint(long mip, long p);
	private native boolean validateF2mGenerator(long mip, long generator, byte[] x, byte[] y);
	private native boolean isF2mMember(long mip, long point);
	private native long createInfinityF2mPoint(long mip);
	private native long createECF2mObject(long mip, int m, int k1, int k2, int k3, byte[] a, byte[] b);
	private native long exponentiateF2mWithPreComputed(long mip, long dlogGroup, long base, byte[] size, int window, int maxBits);
	
	private long nativeDlog = 0;
	
	/**
	 * Default constructor. Initializes this object with K-163 NIST curve.
	 */
	public MiraclDlogECF2m() throws IOException{
		this("K-163");
	}
	
	public MiraclDlogECF2m(String fileName, String curveName) throws IOException{
		super(fileName, curveName);
	}
	/**
	 * Initialize this DlogGroup with one of NIST recommended elliptic curve
	 * @param curveName - name of NIST curve to initialized
	 * @throws IOException 
	 * @throws IllegalAccessException
	 */
	public MiraclDlogECF2m(String curveName) throws IllegalArgumentException, IOException{
		
		Properties ecProperties;
	
		ecProperties = getProperties(PROPERTIES_FILES_PATH); //get properties object containing the curve data
	
		//checks that the curveName is in the file 
		if(!ecProperties.containsKey(curveName)) { 
			throw new IllegalArgumentException("no such NIST elliptic curve"); 
		} 
		this.curveName = curveName;
		//check that the given curve is in the field that matches the group
		if (!curveName.startsWith("B-") && !curveName.startsWith("K-")){
			throw new IllegalArgumentException("curveName is not a curve over F2m field and doesn't match the DlogGroup type"); 
		}
		
		doInit(ecProperties, curveName);  // set the data and initialize the curv
	}
	
	/**
	 * Extracts the parameters of the curve from the properties object and initialize the groupParams, 
	 * generator and the underlying curve
	 * @param ecProperties - properties object contains the curve file data
	 * @param curveName - the curve name as it called in the file
	 */
	protected void doInit(Properties ecProperties, String curveName) {
		//get the curve parameters
		int m = Integer.parseInt(ecProperties.getProperty(curveName));
		int k = Integer.parseInt(ecProperties.getProperty(curveName+"k"));
		String k2Property = ecProperties.getProperty(curveName+"k2");
		String k3Property = ecProperties.getProperty(curveName+"k3");
		BigInteger a = new BigInteger(ecProperties.getProperty(curveName+"a"));
		BigInteger b = new BigInteger(1,Hex.decode(ecProperties.getProperty(curveName+"b")));
		BigInteger x = new BigInteger(1,Hex.decode(ecProperties.getProperty(curveName+"x")));
		BigInteger y = new BigInteger(1,Hex.decode(ecProperties.getProperty(curveName+"y")));
		BigInteger q = new BigInteger(ecProperties.getProperty(curveName+"r"));
		int k2=0;
		int k3=0;
		boolean trinomial;
		
		if (k2Property==null && k3Property==null){ //for trinomial basis
			groupParams = new ECF2mTrinomialBasis(q, x, y, m, k, a, b);
			trinomial = true;
		} else { //pentanomial basis
			k2 = Integer.parseInt(k2Property);
			k3 = Integer.parseInt(k3Property);
			trinomial = false;
			groupParams = new ECF2mPentanomialBasis(q, x, y, m, k, k2, k3, a, b);
		} 
		BigInteger h = null;
		//koblitz curve
		if (curveName.contains("K-")){
			
			if (a.equals(BigInteger.ONE)){
				h = new BigInteger("2");
			} else {
				h = new BigInteger("4");
			}
			groupParams = new ECF2mKoblitz((ECF2mGroupParams) groupParams, q, h);
		}
		
		//create the curve
		if (trinomial == true){
			initF2mCurve(getMip(), m, k, k2, k3, a.toByteArray(), b.toByteArray());
		} else {
			initF2mCurve(getMip(), m, k3, k2, k, a.toByteArray(), b.toByteArray());
		}
		
		//create the generator
		generator = new ECF2mPointMiracl(x,y, this);	
	}
	
	/**
	 * @return the type of the group - ECF2m
	 */
	public String getGroupType(){
		return "elliptic curve over F2m";
	}
	
	/**
	 * Calculates the inverse of the given GroupElement
	 * @param groupElement to inverse
	 * @return the inverse element of the given GroupElement
	 * @throws IllegalArgumentException
	 */
	public GroupElement getInverse(GroupElement groupElement) throws IllegalArgumentException{
		
		//if the GroupElement doesn't match the DlogGroup, throw exception
		if (!(groupElement instanceof ECF2mPointMiracl)){
			throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
		}
		
		//the inverse of infinity point is infinity
		if (((ECF2mPointMiracl)groupElement).isInfinity()){
			return groupElement;
		}
		
		long point = ((ECF2mPointMiracl)groupElement).getPoint();
		//call to native inverse function
		long result = invertF2mPoint(mip, point);
		//build a ECF2mPointMiracl element from the result value
		return new ECF2mPointMiracl(result, this);	
		
	}
	
	/**
	 * Multiplies two GroupElements
	 * @param groupElement1
	 * @param groupElement2
	 * @return the multiplication result
	 * @throws IllegalArgumentException
	 */
	public GroupElement multiplyGroupElements(GroupElement groupElement1, 
						GroupElement groupElement2) throws IllegalArgumentException{
		
		//if the GroupElements don't match the DlogGroup, throw exception
		if (!(groupElement1 instanceof ECF2mPointMiracl)){
			throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
		}
		if (!(groupElement2 instanceof ECF2mPointMiracl)){
			throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
		}
		
		//if one of the points is the infinity point, the second one is the multiplication result
		if (((ECF2mPointMiracl)groupElement1).isInfinity()){
			return groupElement2;
		}
		if (((ECF2mPointMiracl)groupElement2).isInfinity()){
			return groupElement1;
		}
		
		long point1 = ((ECF2mPointMiracl)groupElement1).getPoint();
		long point2 = ((ECF2mPointMiracl)groupElement2).getPoint();
		
		//call to native multiply function
		long result = multiplyF2mPoints(mip, point1, point2);
		//build a ECF2mPointMiracl element from the result value
		return new ECF2mPointMiracl(result, this);
		
	}
	
	/**
	 * Calculates the exponentiate of the given GroupElement
	 * @param exponent
	 * @param base 
	 * @return the result of the exponentiation
	 * @throws IllegalArgumentException
	 */
	public GroupElement exponentiate(GroupElement base, BigInteger exponent) 
									 throws IllegalArgumentException{
		
		//if the GroupElements don't match the DlogGroup, throw exception
		if (!(base instanceof ECF2mPointMiracl)){
			throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
		}
		
		//infinity remains the same after any exponentiate
		if (((ECF2mPointMiracl) base).isInfinity()){
			return base;
		}
		
		long point = ((ECF2mPointMiracl)base).getPoint();
		//call to native exponentiate function
		long result = exponentiateF2mPoint(mip, point, exponent.toByteArray());
		//build a ECF2mPointMiracl element from the result value
		return new ECF2mPointMiracl(result, this);
		
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
		
		//Koblitz curve has an optimization that cause the naive algorithm to be faster than the following optimized algorithm.
		//so currently we operate the naive algorithm instead of the optimized algorithm.
		//may be in the future this will be change.
		if (groupParams instanceof ECF2mKoblitz){
			return computeNaive(groupElements, exponentiations);
		}
		
		int len = groupElements.length;
		
		//Our test results show that for elliptic curve over F2m and n<60 the naive algorithm gives the best performances
		if (len < 60){
				return computeNaive(groupElements, exponentiations);
		} 
		
		long[] nativePoints = new long[len];
		byte[][] exponents = new byte[len][];
		for(int i=0; i<len; i++){
			//if the GroupElements don't match the DlogGroup, throw exception
			if (!(groupElements[i] instanceof ECF2mPointMiracl)){
				throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
			}
			nativePoints[i] = ((ECF2mPointMiracl)groupElements[i]).getPoint();
			exponents[i] = exponentiations[i].toByteArray();
		}
		
		//call to native exponentiate function
		long result = simultaneousMultiplyF2m(mip, nativePoints, exponents);
		//build a ECF2mPointMiracl element from the result value
		return new ECF2mPointMiracl(result, this);
	}
	
	@Override
	public GroupElement exponentiateWithPreComputedValues
			(GroupElement groupElement, BigInteger exponent){
		
		//tests showed that the naive algorithm is faster than the optimized.
		//return exponentiate(groupElement, exponent);
		
		//if the GroupElements don't match the DlogGroup, throw exception
		if (!(groupElement instanceof ECF2mPointMiracl)){
			throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
		}
		
		ECF2mPointMiracl base = (ECF2mPointMiracl)groupElement;
		
		//infinity remains the same after any exponentiate
		if (base.isInfinity()){
			return base;
		}
		
		if (nativeDlog == 0){
			
			int m, k1 = 0, k2 = 0, k3 = 0;
			boolean trinomial = false;
			ECF2mGroupParams params = (ECF2mGroupParams)groupParams;
			BigInteger a, b;
			m = params.getM();
			a = params.getA();
			b = params.getB();
			//create the curve
			if (params instanceof ECF2mKoblitz){
				params = ((ECF2mKoblitz) params).getCurve();
			}
			if (params instanceof ECF2mTrinomialBasis){
				ECF2mTrinomialBasis paramsT = (ECF2mTrinomialBasis) params;
				k1 = paramsT.getK1();
				trinomial = true;
			} else if (params instanceof ECF2mPentanomialBasis){
				ECF2mPentanomialBasis paramsP = (ECF2mPentanomialBasis) params;
				k1 = paramsP.getK1();
				k2 = paramsP.getK2();
				k3 = paramsP.getK3();
				trinomial = false;
			}
			
			if (trinomial){
				nativeDlog = createECF2mObject(mip, m, k1, 0, 0, a.toByteArray(), b.toByteArray());
			} else{
				nativeDlog = createECF2mObject(mip, m, k3, k2, k1, a.toByteArray(), b.toByteArray());
			}
		}
		
		//call to native exponentiate function
		long result = exponentiateF2mWithPreComputed(mip, nativeDlog, base.getPoint(), exponent.toByteArray(), getWindow(), getOrder().bitLength());
		
		//build a ECF2mPointMiracl element from the result value
		return new ECF2mPointMiracl(result, this);
	}
	
	/**
	 * Creates a random member of this Dlog group
	 * @return the random element 
	 */
	public GroupElement getRandomElement() {
		
		return new ECF2mPointMiracl(this);
	}
	
	/**
	 * Creates a point in the F2m field with the given parameters 
	 * @return the random element
	 */
	public ECElement getElement(BigInteger x, BigInteger y) {
		
		return new ECF2mPointMiracl(x, y, this);
	}
	
	/**
	 * Check if the given element is member of this Dlog group
	 * @param element - 
	 * @return true if the given element is member of that group. false, otherwise.
	 * @throws IllegalArgumentException
	 */
	public boolean isMember(GroupElement element){
		
		boolean member = false;
		if(!(element instanceof ECF2mPointMiracl)){
			throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
		}
		
		//infinity point is a valid member
		if (((ECF2mPointMiracl) element).isInfinity()){
			return true;
		}
		
		//call for native function that checks is the element is a point of this curve
		member = isF2mMember(mip, ((ECF2mPointMiracl) element).getPoint());
			
		return member;
	}
	
	public ECElement getInfinity(){
		long infinity = createInfinityF2mPoint(mip);
		return new ECF2mPointMiracl(infinity, this);
	}
	
	/**
	 * Converts a byte array to a ECF2mPointMiracl.
	 * @param binaryString the byte array to convert
	 * @return the created group Element
	 */
	public GroupElement convertByteArrayToGroupElement(byte[] binaryString){
		if (binaryString.length >= ((ECF2mGroupParams) groupParams).getM()){
			throw new IllegalArgumentException("String is too long. It has to be of length less than log p");
		}
		BigInteger  x = new BigInteger(binaryString);
		GroupElement point = null;
		try {
			point = new ECF2mPointMiracl(x, this);
		} catch (IllegalArgumentException e) {
			throw new IllegalArgumentException("The given string is not a valid point to this curve");
		} 
		return point;
	}
	
	/**
	 * Convert a ECF2mPointMiracl to a byte array.
	 * @param groupElement the element to convert
	 * @return the created byte array
	 */
	public byte[] convertGroupElementToByteArray(GroupElement groupElement){
		if (!(groupElement instanceof ECF2mPointMiracl)){
			throw new IllegalArgumentException("element type doesn't match the group type");
		}
		return ((ECElement) groupElement).getX().toByteArray();
	}
	
	//upload MIRACL library
	static {
        System.loadLibrary("MiraclJavaInterface");
	}

}
