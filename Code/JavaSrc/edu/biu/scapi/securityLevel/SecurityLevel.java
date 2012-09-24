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

package edu.biu.scapi.securityLevel;
/**
 * Many cryptographic primitives and schemes have different security levels. 
 * For example, an encryption scheme can be CPA-secure (secure against chosen-plaintext attacks)
 * or CCA-secure (secure against chosen-ciphertext attacks). 
 * The security level of a cryptographic entity is specified by making the implementing class of the entity 
 * declare that it implements a certain security level; for example, an encryption scheme that is CCA-secure will implement the Cca interface. 
 * Different primitives have different families that define their security levels (e.g., hash functions, MACs, encryption). 
 * It is often the case that different security levels of a given primitive form a hierarchy (e.g., any CCA-secure encryption scheme is also CPA-secure), 
 * and in this case they extend each other. Thus, it suffices to implement a Cca interface and this immediately implies that a Cpa interface is also implied. 
 * <p>
 * All of the interfaces expressing a security level are marker interfaces that define types of security level and do not have any functionality.
 *
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 */
public interface SecurityLevel {

}
