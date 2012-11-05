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
package edu.biu.scapi.primitives.trapdoorPermutation;

import java.io.Serializable;
import java.math.BigInteger;

/**
 * This class is an auxiliary class that allows to send the actual data of a TPElement using the Serialization mechanism.
 * This is NOT a TPElement, just the data to possibly create one if you hold the right TrapdoorPermutation. The creation of the TPElement will be performed by the TrapdoorPermutation
 * and will succeed only if the value is valid. The check will be performed by the permutation.
 * The getSendableData() function implemented by the different TPElements extracts the data from the element and puts it in a newly created object TPElementSendableData.
 * The corresponding TrapdoorPermuation can re-generate the serialized TPElement by calling the function generateElement(TPElementSendableData): TPElement.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public final class TPElementSendableData implements Serializable {
	private static final long serialVersionUID = -730490331384046007L;
	//The actual value of the element. (This is NOT a TPElement).
	BigInteger x;
	
	public TPElementSendableData(BigInteger x) {	
		this.x = x;
	}

	public BigInteger getX() {
		return x;
	}
	
	
	
}
