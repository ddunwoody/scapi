package edu.biu.scapi.primitives.dlog.bc;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Properties;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import edu.biu.scapi.primitives.dlog.DlogECF2m;
import edu.biu.scapi.primitives.dlog.ECElement;
import edu.biu.scapi.primitives.dlog.ECF2mUtility;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mGroupParams;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mKoblitz;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mPentanomialBasis;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mTrinomialBasis;
import edu.biu.scapi.securityLevel.DDH;

/**
 * This class implements an Elliptic curve Dlog group over F2m utilizing Bouncy Castle's implementation. 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class BcDlogECF2m extends BcAdapterDlogEC implements DlogECF2m, DDH{

	private ECF2mUtility util = new ECF2mUtility();
	
	/**
	 * Default constructor. Initializes this object with K-163 NIST curve.
	 */
	public BcDlogECF2m() throws IOException{
		this("K-163");
	}
	
	public BcDlogECF2m(String fileName, String curveName) throws IOException{
		super(fileName, curveName);
	}
	
	/**
	 * Constructor that initialize this DlogGroup with one of NIST recommended elliptic curve
	 * @param curveName - name of NIST curve to initialized
	 * @throws IOException 
	 * @throws IllegalAccessException
	 */
	public BcDlogECF2m(String curveName) throws IllegalArgumentException, IOException{
		
		Properties ecProperties;
	
		ecProperties = getProperties(PROPERTIES_FILES_PATH); //get properties object containing the curve data
	
		//checks that the curveName is in the file 
		if(!ecProperties.containsKey(curveName)) { 
			throw new IllegalArgumentException("no such NIST elliptic curve"); 
		} 
			this.curveName = curveName;
		//check that the given curve is in the field that matches the group
		if (!curveName.startsWith("B-") && !curveName.startsWith("K-")){
			throw new IllegalArgumentException("curveName is not a curve over F2m field and doesn't match this DlogGroup type"); 
		}
		
		doInit(ecProperties, curveName);  // set the data and initialize the curve
		
	}
	
	
	/*
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
		BigInteger h = new BigInteger(ecProperties.getProperty(curveName+"h"));
		int k2=0;
		int k3=0;
		boolean trinomial; //sign which basis the curve use
		
		if (k2Property==null && k3Property==null){ //for trinomial basis
			groupParams = new ECF2mTrinomialBasis(q, x, y, m, k, a, b, h);
			trinomial = true;
		
		} else { //pentanomial basis
			k2 = Integer.parseInt(k2Property);
			k3 = Integer.parseInt(k3Property);
			groupParams = new ECF2mPentanomialBasis(q, x, y, m, k, k2, k3, a, b, h);
			trinomial = false;
		} 
		
		//koblitz curve
		if (curveName.contains("K-")){
			
			groupParams = new ECF2mKoblitz((ECF2mGroupParams) groupParams, q, h);
		}
		
		//create the curve of BC
		if (trinomial == true){
			curve = new ECCurve.F2m(m, k, a, b, q, h);
		} else {
			curve = new ECCurve.F2m(m, k, k2, k3, a, b, q, h);
		}
		
		//create the generator
		generator = new ECF2mPointBc(x,y, this);
			
	}
	
	/**
	 * @return the type of the group - ECF2m
	 */
	public String getGroupType(){
		return "elliptic curve over F2m";
	}
	
	/*
	 * Checks if the given element is a member of this Dlog group
	 * @param element 
	 * @return true if the given element is member of this group; false, otherwise.
	 * @throws IllegalArgumentException
	 */
	public boolean isMember(GroupElement element) throws IllegalArgumentException{
		
		if (!(element instanceof ECF2mPointBc)){
			throw new IllegalArgumentException("element type doesn't match the group type");
		}
		
		ECF2mPointBc point = (ECF2mPointBc) element;
		
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

		boolean valid = util.checkCurveMembership((ECF2mGroupParams) groupParams, point.getX(), point.getY());
		valid = valid && util.checkSubGroupMembership(this, point);
		
		return valid;
			
	}
	
	/**
	 * Creates a point over F2m field with the given parameters
	 * @return the created point
	 */
	public ECElement generateElement(BigInteger x, BigInteger y) throws IllegalArgumentException{
		//Creates element with the given values.
		ECF2mPointBc point =  new ECF2mPointBc(x, y, this);
		
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
	 * Creates ECPoint.F2m with the given parameters
	 */
	protected GroupElement createPoint(ECPoint result) {
		return new ECF2mPointBc(result);
	}
	
	/**
	 * Check if the element is valid to this elliptic curve group
	 */
	protected boolean checkInstance(GroupElement element){
		if (element instanceof ECF2mPointBc){
			return true;
		} else {
			return false;
		}
	}
	
	/**
	 * Creates ECPoint.F2m with infinity values
	 */
	public ECElement getInfinity(){
		ECPoint infinity = curve.getInfinity();
		return new ECF2mPointBc(infinity);
	}
	
	/**
	 * Converts a byte array to an ECF2mPointBc.
	 * @param binaryString the byte array to convert
	 * @return the created group Element
	 */
	public GroupElement convertByteArrayToGroupElement(byte[] binaryString){
		//currently we don't support this conversion. 
		//will be implemented in the future.
		return null;
	}
	
	/**
	 * Convert a ECF2mPointBc to a byte array.
	 * @param groupElement the element to convert
	 * @return the created byte array
	 */
	public byte[] convertGroupElementToByteArray(GroupElement groupElement){
		if (!(groupElement instanceof ECF2mPointBc)){
			throw new IllegalArgumentException("element type doesn't match the group type");
		}
		//currently we don't support this conversion. 
		//will be implemented in the future.
		return null;
	}
	

}