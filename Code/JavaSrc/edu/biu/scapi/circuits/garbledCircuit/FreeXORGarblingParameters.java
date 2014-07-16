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
import edu.biu.scapi.circuits.encryption.MultiKeyEncryptionScheme;
import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.primitives.kdf.KeyDerivationFunction;
import edu.biu.scapi.primitives.kdf.bc.BcKdfISO18033;

/**
 * This is the garbling parameters' class for a Free XOR circuit.<p>
 * A Free XOR circuit's parameters are:<p>
 * 1. The boolean circuit that needs to be garbled. <p>
 * 2. A MultiKeyEncryptionScheme.<p>
 * 3. A KeyDerivationFunction, in case the user wants to use the Row Reduction algorithm.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class FreeXORGarblingParameters implements GarblingParameters{
	
	private BooleanCircuit ungarbledCircuit;
	private MultiKeyEncryptionScheme mes;
	private KeyDerivationFunction kdf;
	private boolean isRowReduction;
	
	/**
	 * This constructor creates a garbling parameters' object for a regular representation of FreeXORGarbledBooleanCircuit.
	 * @param ungarbledCircuit The boolean circuit that needs to be garbled. 
	 * @param mes A MultiKeyEncryptionScheme to use.
	 * @param isRowReduction Indicates if the circuit should use the row reduction algorithm or not.
	 */
	public FreeXORGarblingParameters(BooleanCircuit ungarbledCircuit, MultiKeyEncryptionScheme mes, boolean isRowReduction){
		this.ungarbledCircuit = ungarbledCircuit;
		this.mes = mes;
		this.isRowReduction = isRowReduction;
		
		if (isRowReduction){
			try {
				kdf = new BcKdfISO18033("SHA-256");
			} catch (FactoriesException e) {
				// Should not occur since the given parameters are implemented.
			}
		}
	}
	
	@Override
	public void setKDF(KeyDerivationFunction kdf){
		if(!isRowReduction){
			throw new IllegalStateException("the setKDF function should be called in case of row reduction only");
		}
		this.kdf = kdf;
	}

	@Override
	public BooleanCircuit getUngarbledCircuit() {
		
		return ungarbledCircuit;
	}
	
	/**
	 * If the constructor with the KDF object was called, the returned utility class uses the rowReduction technology.
	 * If not, the returned utility class uses the regular garbled table.
	 */
	@Override
	public CircuitTypeUtil createCircuitUtil() {
		if (!isRowReduction){ //There is no kdf, return the regular Free XOR utility.
			return new FreeXORGarbledBooleanCircuitUtil(mes);
		} else { //There is a kdf, return the Row Reduction Free XOR utility.
			return new FreeXORRowReductionGarbledBooleanCircuitUtil(mes, kdf);
		}
	}
	
	@Override
	public KeyDerivationFunction getKDF(){
		return kdf;
	}

}
