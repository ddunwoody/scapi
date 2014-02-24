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

import java.security.InvalidKeyException;

import edu.biu.scapi.circuits.circuit.BooleanCircuit;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.primitives.prg.PseudorandomGenerator;

/**
 * General interface for Garbled Boolean circuit that was generated via pseudo random generator and seed.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public interface GarbledBooleanCircuitSeedGeneration extends GarbledBooleanCircuit{
	
	/**
	 * This method generates both keys for each input wire using the given prg and seed. 
	 * Then, creates the garbled table according to that values.<p>
	 * @param ungarbledCircuit the circuit that this {@code GarbledBooleanCircuit} is supposed to be a garbling of. 
	 * @param prg used to generate the garbled values.
	 * @param seed used to initialize the given prg.
	 * @param hash CryptographicHash object used to compute the hash function on the circuit's garbled tables.
	 * @return CircuitCreationValues contains both keys for each input and output wire and the translation table.
	 * @throws InvalidKeyException in case the seed is invalid key for the given PRG.
	 */
	public CircuitSeedCreationValues garble(BooleanCircuit ungarbledCircuit, PseudorandomGenerator prg, byte[] seed, CryptographicHash hash) throws InvalidKeyException ;
		
	/**
     * The verify method is used in the case of malicious adversaries.<p>
     * Alice constructs n circuits and Bob can verify n-1 of them(of his choosing) to confirm that they are indeed garbling of the 
     * agreed upon non garbled circuit. <p>
     * 
     * This verify method verifies that the given hashedCircuits is indeed the result of the given hash function 
     * on the garbled tables created by the given prg and seed.<p>
     * 
     * In order to verify, Alice has to give Bob the prg and the seed used to generate the keys, along with the hash function 
     * and the result of the hash on the garbled tables of p1.<p>
     * The function calculates the garbled tables on the fly, meaning it calculates the garbled table of each gate, computes the hash on it and drops it.
     * 
     * @param ungarbledCircuit the circuit that this {@code GarbledBooleanCircuit} is supposed to be a garbling of. 
     * @param prg used to generate both keys for each input wire.
     * @param seed used to initialize the given prg
     * @param hash CryptographicHash object used to compute the hash function on the circuit's garbled tables.
     * @param hashedCircuit the result of the hash on the garbled tables of p1.
     * @return {@code true} if this {@code GarbledBooleanCircuit} is a garbling of the ungarbledCircuit, {@code false} if it is not
	 * @throws InvalidKeyException in case the seed is invalid key for the given PRG.
     * 
     */
	public boolean verify(BooleanCircuit ungarbledCircuit, PseudorandomGenerator prg, byte[] seed, CryptographicHash hash, byte[] hashedCircuit) throws InvalidKeyException;
  
	/**
	 * Verifies that the given hashedCircuit is indeed the hash of the garbled table of this circuit.
	 * @param hash used to hash the garbled tables
	 * @param hashedCircuit should be equal to the hash of this garbledTables.
	 * @return true if the given hashedCircuit is indeed the hash of the garbled table of this circuit; false, otherwise.
	 */
	public boolean verifyGarbledTables(CryptographicHash hash, byte[] hashedCircuit) ;
	  
}
