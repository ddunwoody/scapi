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
package edu.biu.scapi.circuits.garbledCircuit;

import edu.biu.scapi.circuits.circuit.BooleanCircuit;
import edu.biu.scapi.primitives.kdf.KeyDerivationFunction;

/**
 * A general interface for a circuits' garbling parameters.<p>
 * Each type of a circuit (standard, FreeXor, MinimizeAESSetKey, etc) has different parameters and should have a related garbling parameters' class.<p>
 * All parameters classes should implement this interface.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public interface GarblingParameters {
	
	/**
	 * Creates and returns a unique utility class.<p>
	 * There are some functionalities in the circuit that have different implementations in different kinds of circuit.
	 * In case of such function, the circuit calls a utility class corresponding to the concrete circuit. 
	 * The utility class is given to the circuit in the construct time by the input object, using this function.
	 * The parameters class is specific for each circuit so it knows exactly which utility class to create.
	 * @return the created utility object.
	 */
	public CircuitTypeUtil createCircuitUtil();
	
	/**
	 * @return the boolean circuit that was garbled.
	 */
	public BooleanCircuit getUngarbledCircuit();
	
	/**
	 * Sets a KDf object that uses in the row reduction technique.
	 * @param kdf to use in the row reduction technique.
	 */
	public void setKDF(KeyDerivationFunction kdf);
	
	/**
	 * Returns the KDF object used in the row reduction technique.
	 */
	public KeyDerivationFunction getKDF();

}
