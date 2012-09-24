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
 * This interface should be used for any primitive, scheme or protocol that achieves perfect security (e.g., a perfect MAC, one-time pad, perfectly-secure multiparty protocol, and so on).<p> 
 * Note that by default, all schemes are computationally secure and so not implementing Perfect or Statistical should be interpreted as computational security.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public interface Perfect extends Statistical {

}
