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
/**
 * Project: scapi.
 * Package: edu.biu.scapi.tools.Provider.
 * File: ScapiProvider.java.
 * Creation date Apr 7, 2011
 * Created by LabTest
 *
 *
 * This file TODO
 */
package edu.biu.scapi.tools.Provider;

import java.security.Provider;

/**
 * @author LabTest
 *
 */
public final class ScapiProvider extends Provider {

	private static final long serialVersionUID = 5008575665601412726L;

	public ScapiProvider() {
	    super("SCAPI", 1.0, "SCAPI Provider");
	    put("MessageDigest.SHA-1", "edu.biu.scapi.tools.Provider.Hash.MessageDigestProvider$SHA1");
        put("Alg.Alias.MessageDigest.SHA1", "SHA-1");
        put("Alg.Alias.MessageDigest.SHA", "SHA-1");
        
        put("MessageDigest.SHA-224", "edu.biu.scapi.tools.Provider.Hash.MessageDigestProvider$SHA224");
        put("Alg.Alias.MessageDigest.SHA224", "SHA-224");
        put("MessageDigest.SHA-256", "edu.biu.scapi.tools.Provider.Hash.MessageDigestProvider$SHA256");
        put("Alg.Alias.MessageDigest.SHA256", "SHA-256");
        put("MessageDigest.SHA-384", "edu.biu.scapi.tools.Provider.Hash.MessageDigestProvider$SHA384");
        put("Alg.Alias.MessageDigest.SHA384", "SHA-384");
        put("MessageDigest.SHA-512", "edu.biu.scapi.tools.Provider.Hash.MessageDigestProvider$SHA512");
        put("Alg.Alias.MessageDigest.SHA512", "SHA-512");
     
        
        
	  }

}
