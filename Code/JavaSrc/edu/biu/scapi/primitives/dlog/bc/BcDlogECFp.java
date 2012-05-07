package edu.biu.scapi.primitives.dlog.bc;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Properties;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import edu.biu.scapi.primitives.dlog.DlogECFp;
import edu.biu.scapi.primitives.dlog.ECElement;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.groupParams.ECFpGroupParams;
import edu.biu.scapi.securityLevel.DDH;

/**
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class BcDlogECFp extends BcAdapterDlogEC implements DlogECFp, DDH{
	
	/**
	 * Default constructor. Initializes this object with P-192 NIST curve.
	 */
	public BcDlogECFp() throws IOException{
		this("P-192");
	}
	
	public BcDlogECFp(String fileName, String curveName) throws IOException{
		super(fileName, curveName);
	}
	
	/**
	 * Initialize this DlogGroup with one of NIST recommended elliptic curve
	 * @param curveName - name of NIST curve to initialized
	 * @throws IOException 
	 * @throws IllegalAccessException
	 */
	public BcDlogECFp(String curveName) throws IllegalArgumentException, IOException{
		
		Properties ecProperties = getProperties(PROPERTIES_FILES_PATH); //get properties object containing the curve data
	
		//checks that the curveName is in the file
		if(!ecProperties.containsKey(curveName)) { 
			throw new IllegalArgumentException("no such NIST elliptic curve"); 
		} 
			this.curveName = curveName;
		//check that the given curve is in the field that matches the group
		if (!curveName.startsWith("P-")){
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
	protected void doInit(Properties ecProperties, String curveName){
		
		//get the nist parameters
		BigInteger p = new BigInteger(ecProperties.getProperty(curveName));
		BigInteger a = new BigInteger(ecProperties.getProperty(curveName+"a"));
		BigInteger b = new BigInteger(1,Hex.decode(ecProperties.getProperty(curveName+"b")));
		BigInteger x = new BigInteger(1,Hex.decode(ecProperties.getProperty(curveName+"x")));
		BigInteger y = new BigInteger(1,Hex.decode(ecProperties.getProperty(curveName+"y")));
		BigInteger q = new BigInteger(ecProperties.getProperty(curveName+"r"));
		
		//create the GroupParams
		groupParams = new ECFpGroupParams(q, x, y, p, a, b);
		
		//create the ECCurve
		curve = new ECCurve.Fp(p, a, b);
		
		generator = new ECFpPointBc(x,y, this);	
	}
	
	/**
	 * @return the type of the group - ECFp
	 */
	public String getGroupType(){
		return "elliptic curve over Fp";
	}
	
	/**
	 * Create a random member of this Dlog group
	 * @return the random element
	 */
	public GroupElement getRandomElement(){
		
		return new ECFpPointBc(this);
	}
	 
	/**
	 * Creates a point over Fp field. 
	 * @return the created point
	 */
	public ECElement getElement(BigInteger x, BigInteger y){
		
		return new ECFpPointBc(x, y, this);
	}
	
	/**
	 * Creates ECPoint.Fp with the given parameters
	 */
	protected GroupElement createPoint(ECPoint result) {
		return new ECFpPointBc(result);
	}
	
	/**
	 * Creates ECPoint.Fp with infinity values
	 */
	public ECElement getInfinity(){
		ECPoint infinity = curve.getInfinity();
		return new ECFpPointBc(infinity);
	}
	
	/**
	 * Converts a byte array to an ECFpPointBc.
	 * @param binaryString the byte array to convert
	 * @return the created group Element
	 */
	public GroupElement convertByteArrayToGroupElement(byte[] binaryString){
		
		if (binaryString.length >= ((ECFpGroupParams) groupParams).getP().bitLength()){
			throw new IllegalArgumentException("String is too long. It has to be of length less than log p");
		}
		BigInteger  x = new BigInteger(binaryString);
		GroupElement point = null;
		try {
			point = new ECFpPointBc(x, this);
		} catch (IllegalArgumentException e) {
			throw new IllegalArgumentException("The given string is not a valid point to this curve");
		} 
		return point;
	}
	
	/**
	 * Convert a ECFpPointBc to a byte array.
	 * @param groupElement the element to convert
	 * @return the created byte array
	 */
	public byte[] convertGroupElementToByteArray(GroupElement groupElement){
		if (!(groupElement instanceof ECFpPointBc)){
			throw new IllegalArgumentException("element type doesn't match the group type");
		}
		return ((ECElement) groupElement).getX().toByteArray();
	}
	
}
