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

import edu.biu.scapi.primitives.hash.CryptographicHash;

/**
 * This interface is an extension for the basic garbled boolean circuit, GarbledBooleanCircuit. <p>
 * The goal was to keep the basic garbled circuit as much simple as possible, and put all the extended possibilities and features in a different interface.<p>
 * This interface should be used in the case of malicious adversaries, thus it adds some related functions. <p>
 * The most important features here are:<p>
 * 1. The ability to set the input or/and output garbled values.<p>
 * 2. The ability to sample the garbled values using a given seed.<p>
 * There are also some additional verify function that matches these features.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public interface GarbledBooleanCircuitExtended extends GarbledBooleanCircuit{

	/**
	 * Gets the input keys, which are the input garbled values and sets them. 
	 * This way when calling the garble function the input values will not be sampled but taken from the given values.
	 * @param inputValues contains both garbled values for each input wire.
	 */
	public void setInputKeys(Map<Integer, SecretKey[]> inputValues);
	
	/**
	 * Gets the output keys, which are the output garbled values and sets them. 
	 * This way when calling the garble function the output values will not be sampled but taken from the given values.
	 * @param outputValues contains both garbled values for each output wire.
	 */
	public void setOutputKeys(Map<Integer, SecretKey[]> outputValues);
	
	/**
	 * Compute the hash function on the garbled tables and translation table of the circuit.
	 * @param hash CryptographicHash function object to use.
	 * @return The result of the hash function on the circuit.
	 */
	public byte[] getHashedCircuit(CryptographicHash hash);
	
	/**
	 * Verifies that the given hashedCircuit is indeed the result of the given hash on the circuit's garbled tables and translation table.
	 * @param hash CryptographicHash function object to use.
	 * @param hashedCircuit A byte array that suppose to be the result of the hash function on the circuit.
	 * @return true if the given hashedCircuit is indeed the result of the hash function of the circuit; False, otherwise.
	 */
	public boolean verifyHashedCircuit(CryptographicHash hash, byte[] hashedCircuit);
	
	/**
     * The verify method is used in the case of malicious adversaries.<p>
     * Alice constructs n circuits and Bob can verify n-1 of them (of his choice) to confirm that they are indeed garbling of the 
     * agreed upon non garbled circuit. In order to verify, Alice has to give Bob both keys for each of the input wires.<p>
     * 
     * This verify function is the same as the verify(Map<Integer, SecretKey[]> allInputWireValues) but also check that the 
     * resulted output garbled values are equal to the given allOutputWireValues.<p>
     * 
     * @param allInputWireValues A {@Map} containing both keys for each input wire.
     * For each input wire index, the map contains an array of two values. The value in the 0 position is the 0 encoding, and the
     * value in the 1 position is the 1 encoding.
     * @param allOutputWireValues A {@Map} containing both keys for each output wire. 
     * The generated output garbled values are checked against these values to see if they are equal.
     * For each output wire index, the map contains an array of two values. The value in the 0 position is the 0 encoding, and the
     * value in the 1 position is the 1 encoding.
     * 
     * @return {@code true} if this {@code GarbledBooleanCircuitExtended} is a garbling the given keys, {@code false} if it is not.
     */
	public boolean verify(Map<Integer, SecretKey[]> allInputWireValues, Map<Integer, SecretKey[]> allOutputWireValues) ;
	
	/**
	 * The verify method is used in the case of malicious adversaries.<p>
	 * Alice constructs n circuits and Bob can verify n-1 of them (of his choice) to confirm that they are indeed garbling of the 
     * agreed upon non garbled circuit. In order to verify, Alice has to give Bob both keys for each of the input wires.<p>
     * 
     * This verify function samples the keys using the given seed, then compute the hash function on the circuit's garbled tables and 
     * translation table and check that the result is equal to the given hashedCircuit.<p>
     * 
	 * @param seed to use in order to generate the keys.
	 * @param allInputGarbledValues A {@Map} containing both keys for each input wire. 
	 * Should be null in case the user set no input garbled values before garbling.
	 * @param allOutputGarbledValues A {@Map} containing both keys for each output wire.
	 * Should be null in case the user set no output garbled values before garbling.
	 * @param hash CryptographicHash object to use.
	 * @param hashedCircuit A byte array that suppose to be the result of the hash function on the circuit.
	 * @return {@code true} if this {@code GarbledBooleanCircuitExtended} is a garbling the given seed, {@code false} if it is not.
	 * @throws InvalidKeyException
	 */
	public boolean verify(byte[] seed, Map<Integer, SecretKey[]> allInputGarbledValues, Map<Integer, SecretKey[]> allOutputGarbledValues, CryptographicHash hash, byte[] hashedCircuit) throws InvalidKeyException;
}
