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

import java.security.SecureRandom;

import edu.biu.scapi.circuits.circuit.BooleanCircuit;
import edu.biu.scapi.primitives.kdf.KeyDerivationFunction;
import edu.biu.scapi.primitives.prf.AES;

/**
 * This is the input class for MinimizeAESSetKey circuit.<p>
 * MinimizeAESSetKey circuit's inputs are:<p>
 * 1. The boolean circuit needs to be garbled. <p>
 * 2. An AES object.<p>
 * 3. A SecureRandom object.<p>
 * 4. A KeyDerivationFunction, in case the user wants to use the Row Reduction algorithm.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class MinimizeAESSetKeyCircuitInput implements CircuitInput{
	private BooleanCircuit ungarbledCircuit;
	private SecureRandom random;
	private KeyDerivationFunction kdf;
	private AES aes;
	private boolean isRowReductionWithFixedOutputKeys;
	
	/**
	 * This constructor creates an input object for a regular representation of MinimizeAESSetKeyGarbledBooleanCircuit.
	 * @param ungarbledCircuit The boolean circuit that needs to be garbled. 
	 * @param aes An AES object to use.
	 * @param random
	 */
	public MinimizeAESSetKeyCircuitInput(BooleanCircuit ungarbledCircuit, AES aes, SecureRandom random){
		this(ungarbledCircuit, aes, null, random, false);
	}
	
	/**
	 * This constructor creates an input object for a row reduction representation of MinimizeAESSetKeyGarbledBooleanCircuit.
	 * @param ungarbledCircuit The boolean circuit that needs to be garbled. 
	 * @param aes An AES object to use.
	 * @param random
	 * @param kdf To use in the row reduction algorithm.
	 * @param isRowReductionWithFixedOutputKeys Indicates if the user is going to sample the wires' keys from given output keys.
	 * In this case, the circuit representation should be a little different. 
	 * See {@link BooleanCircuit#BooleanCircuit(File f)} for more information.
	 */
	public MinimizeAESSetKeyCircuitInput(BooleanCircuit ungarbledCircuit, AES aes, KeyDerivationFunction kdf, SecureRandom random, boolean isRowReductionWithFixedOutputKeys){
		this.ungarbledCircuit = ungarbledCircuit;
		this.random = random;
		this.kdf = kdf;
		this.aes = aes;
		this.isRowReductionWithFixedOutputKeys = isRowReductionWithFixedOutputKeys;
	}

	@Override
	public BooleanCircuit getUngarbledCircuit() {
		
		return ungarbledCircuit;
	}
	
	@Override
	/**
	 * If the constructor with the KDF object was called, the returned utility class uses the rowReduction technology.
	 * If not, the returned utility class uses the regular garbled table.
	 */
	public CircuitTypeUtil createCircuitUtil() {
		
		if (kdf == null){ //There is no kdf, return the regular MinimizeAESSetKey utility.
			return new MinimizeAESSetKeyGarbledBooleanCircuitUtil(aes, random);
		} else{ //There is a kdf, return the Row Reduction MinimizeAESSetKey utility.
			return new MinimizeAESSetKeyRowReductionGarbledBooleanCircuitUtil(aes, kdf, random, isRowReductionWithFixedOutputKeys, ungarbledCircuit.getOutputWireLabels());
		}
		
	}
	
	public boolean isRowReductionWithFixedOutputKeys(){
		return isRowReductionWithFixedOutputKeys;
	}
	
	public KeyDerivationFunction getKDF(){
		return kdf;
	}
		
}
