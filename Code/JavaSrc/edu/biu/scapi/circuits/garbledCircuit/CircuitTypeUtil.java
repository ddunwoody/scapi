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
import java.util.Map;

import javax.crypto.SecretKey;

import edu.biu.scapi.circuits.circuit.BooleanCircuit;
import edu.biu.scapi.circuits.circuit.Gate;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.primitives.prg.PseudorandomGenerator;

/**
 * A general interface contains some functionalities that are different in each circuit type. <p>
 * For example, keys generation is done differently in each circuit type. 
 * In Standard garbled circuit all keys are random bits; In FreeXOR circuit, the keys for each wire are XOR of each other with some delta.
 * 
 * In addition, the gates in each circuit are in different types. So, this interface also contains a function that creates the gates.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
interface CircuitTypeUtil {
	
	/**
	 * Creates the gates that match this circuit type.
	 * @param ungarbledGates the gates that should be garbled.
	 * @param garbledTablesHolder holds the arbled tables.
	 * @return the created garbled gates.
	 */
	public GarbledGate[] createGates(Gate[] ungarbledGates, GarbledTablesHolder garbledTablesHolder);
	
	/**
	 * This method generates both keys for each input wire. Then, creates the garbled table according to that values.<p>
	 * @param ungarbledCircuit the circuit that this {@code GarbledBooleanCircuit} is supposed to be a garbling of.
	 * @param garbledTablesHolder the object that points to the garbledTable.
	 * @param gates the gates of this circuit. 
	 * @return CircuitCreationValues contains both keys for each input and output wire, the translation table and the signal bits of the input wires.
	 */
	public CircuitCreationValues generateWireKeysAndSetTables(BooleanCircuit ungarbledCircuit, GarbledTablesHolder garbledTablesHolder, 
			GarbledGate[] gates);
	
	/**
	 * This method gets part of the keys and generates the missing keys for all circuit's wires. 
	 * Then, creates the garbled table according to that values.<p>
	 * This method can receive the keys of the input wires or the keys of the output wires.<p>
	 * In addition, it gets the signal bits corresponding to the partial wire's keys. 
	 * In case the given keys are the keys of the output wires than the given signal bits are actually the translation table.
	 * 
	 * @param ungarbledCircuit the circuit that this {@code GarbledBooleanCircuit} is supposed to be a garbling of.
	 * @param garbledTablesHolder the object that points of the garbledTable.
	 * @param gates the gates of this circuit.
	 * @param partialWireValues can contain the keys of the input wires or the keys of the output wires.
	 * Note: The list significant bit of the input and output keys of each wire should be different. 
	 * Meaning, for each wire, if the last bit of k0 is 0, the last bit of k1 must be 1. 
	 * Clearly, the content of the last bit of all k0 should be picked at random. Else, the circuit is not secure. 
	 * @return CircuitCreationValues contains both generated values for each input and output wire and the translation table.
	 */
	public CircuitCreationValues generateWireKeysAndSetTables(BooleanCircuit ungarbledCircuit, GarbledTablesHolder garbledTablesHolder, 
			GarbledGate[] gates, Map<Integer, SecretKey[]> partialWireValues) ;
	
	/**
	 * This method generates both keys for each input wire using the given prg and seed. 
	 * Then, creates the garbled table according to that values.<p>
	 * @param ungarbledCircuit the circuit that this {@code GarbledBooleanCircuit} is supposed to be a garbling of. 
	 * @param garbledTablesHolder the object that points of the garbledTable.
	 * @param prg used to generate the garbled values.
	 * @param seed used to initialize the given prg.
	 * @param hash CryptographicHash object used to compute the hash function on the circuit's garbled tables.
	 * @return CircuitCreationValues contains both generated values for each input and output wire and the translation table.
	 * @throws InvalidKeyException in case the seed is invalid key for the given PRG.
	 */
	public CircuitSeedCreationValues generateWireKeysAndSetTables(BooleanCircuit ungarbledCircuit, GarbledTablesHolder garbledTablesHolder, 
			GarbledGate[] gates, PseudorandomGenerator prg, byte[] seed, CryptographicHash hash) throws InvalidKeyException;
	
	/**
	 * Calculates the garbled table of each gate using the given ungarbled circuit, prg and seed. 
	 * Then, update the hash function with the garbled table and drop it.<p>
	 * Nothing is kept in memory. 
	 * @param ungarbledCircuit the circuit that this {@code GarbledBooleanCircuit} is supposed to be a garbling of. 
	 * @param prg used to generate both keys for each input wire.
     * @param seed used to initialize the given prg
     * @param hash CryptographicHash object used to compute the hash function on the circuit's garbled tables.
	 * @return the result of the hash function on the garbled tables.
	 * @throws InvalidKeyException in case the seed is invalid key for the given PRG.
	 */
	public byte[] getHashedTables(BooleanCircuit ungarbledCircuit, PseudorandomGenerator prg, byte[] seed, CryptographicHash hash) throws InvalidKeyException;
		
}
