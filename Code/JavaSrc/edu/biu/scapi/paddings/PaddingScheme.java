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
package edu.biu.scapi.paddings;


/**
 * General interface for padding scheme. Every padding scheme, for example PKCS7, should implement this interface.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public interface PaddingScheme{
	/**
	 * Pads the given byte array with padSize bytes according to this padding scheme.
	 * @param padInput array to pad
	 * @param padSize number of bytes to add to padInput array
	 * @return the padded array
	 */
	public byte[] pad(byte[] padInput, int padSize);
	
	/**
	 * Removes the padding from the given byte array according to this padding scheme.
	 * @param paddedInput array to remove the padding from
	 * @return the array without the padding
	 */
	public byte[] removePad(byte[] paddedInput);
}
