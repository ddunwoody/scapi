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
 * This hierarchy specifies the security level of encryption schemes; it does not differentiate between symmetric and asymmetric encryption. 
 * There are two sub-hierarchies for encryption. The first relates to the adversarial power and includes Eav (eavesdropping adversary), CPA (chosen-plaintext attack), 
 * CCA1 (preprocessing chosen-ciphertext attack), and CCA2 (full chosen-ciphertext attack). The second relates to the aim of the attack and includes Indistinguishable (for the standard indistinguishability notion) and NonMalleable; 
 * note that non-malleability implies indistinguishability and thus the NonMalleable interface extends the Indistinguishable interface.  
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public interface EncSecLevel extends SecurityLevel {

}
