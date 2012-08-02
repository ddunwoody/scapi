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
package edu.biu.scapi.primitives.prf;

/** 
 * General interface for pseudorandom permutation with varying input and output lengths. 
 * A pseudorandom permutation with varying input/output lengths does not have predefined input /output lengths. 
 * The input and output length (that must be equal) may be different for each function call. 
 * The length of the input and output is determined upon user request. 
 * The interface PrpVaryingIOLength, groups and provides type safety for every PRP with varying input/output length. 
 * 
  * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public interface PrpVaryingIOLength extends PseudorandomPermutation,
		PrfVaryingIOLength {
}
