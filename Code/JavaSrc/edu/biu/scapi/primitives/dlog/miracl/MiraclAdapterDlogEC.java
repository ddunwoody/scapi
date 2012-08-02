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
package edu.biu.scapi.primitives.dlog.miracl;



import java.io.IOException;

import edu.biu.scapi.primitives.dlog.DlogEllipticCurve;
import edu.biu.scapi.primitives.dlog.DlogGroupEC;

public abstract class MiraclAdapterDlogEC extends DlogGroupEC 
										  implements DlogEllipticCurve{
	
	protected int window = 0;
	protected MiraclAdapterDlogEC(){}
	
	public MiraclAdapterDlogEC(String fileName, String curveName) throws IOException {
		super(fileName, curveName);
	}

	private native long createMip();

	protected long mip; ///MIRACL pointer

	/*
	 * 
	 * @return mip - miracl pointer
	 */
	public long getMip(){
		if (mip==0)
			mip = createMip();
		return mip;
	}
	
	public void setWindow(int val){
		window = val;
	}
	
	protected int getWindow(){
		if (window != 0){
			return window;
		}
		int bits = getOrder().bitLength();
		if (bits <= 256){
			window =  8;
		} else {
			window = 10;
		}
		return window;
	}
	
}

