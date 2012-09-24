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
 * This hierarchy specifies the security level of a message authentication code (MAC) or digital signature scheme.<p> 
 * The hierarchy here only refers to the number of times that the MAC or signature scheme can be used; namely, OneTime or UnlimitedTimes. 
 * We do not currently have another interface for a bounded but not unlimited number of times; if necessary this can be added later. 
 * We also consider by default adaptive chosen-message attacks and so have not defined a separate hierarchy for adaptive/non-adaptive attacks and chosen versus random message attacs.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public interface MacSignSecLevel extends SecurityLevel {

}
