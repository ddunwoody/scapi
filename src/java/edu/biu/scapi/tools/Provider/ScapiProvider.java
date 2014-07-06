/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2012 - SCAPI (http://crypto.biu.ac.il/scapi)
* This file is part of the SCAPI project.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
* 
* We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to
* http://crypto.biu.ac.il/SCAPI.
* 
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
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
