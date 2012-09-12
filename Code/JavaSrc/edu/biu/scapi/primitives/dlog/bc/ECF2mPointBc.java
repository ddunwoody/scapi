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

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECFieldElement.F2m;
import org.bouncycastle.math.ec.ECPoint;

import edu.biu.scapi.primitives.dlog.ECF2mPoint;
import edu.biu.scapi.primitives.dlog.ECF2mUtility;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mGroupParams;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mKoblitz;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mPentanomialBasis;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mTrinomialBasis;
import edu.biu.scapi.primitives.dlog.groupParams.GroupParams;

/**
 * This class is an adapter for ECPoint.F2m of BC
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 * 
 */
public class ECF2mPointBc extends ECPointBc implements ECF2mPoint {
	private ECF2mUtility util = new ECF2mUtility();
	
	/**
	 * Constructor that accepts x,y values of a point. 
	 * if the values are valid - set the point.
	 * @param x
	 * @param y
	 * @param curve - DlogGroup
	 */
	ECF2mPointBc(BigInteger x, BigInteger y, BcDlogECF2m curve) throws IllegalArgumentException{

		boolean valid = util.checkCurveMembership((ECF2mGroupParams) curve.getGroupParams(), x, y);
		// checks validity
		if (valid == false) // if not valid, throws exception
			throw new IllegalArgumentException("x, y values are not a point on this curve");

		/* create point with the given parameters */
		point = curve.createPoint(x, y);
	}
	
	/*
	 * Constructor that gets an element and sets it.
	 * Only our inner functions use this constructor to set an element. 
	 * The ECPoint is a result of our DlogGroup functions, such as multiply.
	 * @param point
	 */
	ECF2mPointBc(ECPoint point) {
		this.point = point;
	}
	
	private void getBasis(GroupParams params, int[] k) {
		
		if (params instanceof ECF2mTrinomialBasis) {
			k[0] = ((ECF2mTrinomialBasis) params).getK1();
		}
		if (params instanceof ECF2mPentanomialBasis) {
			k[0] = ((ECF2mPentanomialBasis) params).getK1();
			k[1] = ((ECF2mPentanomialBasis) params).getK2();
			k[2] = ((ECF2mPentanomialBasis) params).getK3();
		}
	}

}
