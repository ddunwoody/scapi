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

import edu.biu.scapi.circuits.circuit.Gate;
import edu.biu.scapi.circuits.encryption.AES128MultiKeyEncryption;
import edu.biu.scapi.primitives.prf.AES;
import edu.biu.scapi.primitives.prf.cryptopp.CryptoPpAES;


/**
 * Our code is designed as such that in its constructor {@link StandardGarbledBooleanCircuitUtil} constructs {@code StandardGarbledGate}s.<p>
 * Each {@code StandardGarbledGate} garbled itself by creating a garbled truth table. The garble truth table is created row by row. 
 * Thus, if we use {@link AES128MultiKeyEncryption} first we will garble the first row, then the second row etc.. 
 * Each row will require two AES operations and two setKey operations--i.e. the key will be set to the garbled value for each row. <p>
 * However, AES set key operations are expensive, and different rows of the truth tables use the same keys. <p>
 * Consider a 2 input gate. There are a total of four keys(a 0 and a 1 for each wire). Yet if we use
 * {@code StandardGarbledBooleanCircuitUtil} with {@code AES128MultiKeyEncryption} we will perform a total of 8 setKey operations. 
 * If we garbled the entire truth table together, however, we would be able to minimize this to 4 operations. </p>
 * <p>
 * In order to minimize the number of row operations, we have to couple the garbled gate and the encryption scheme. They can no longer 
 * be totally separate entities. This presents an issue, however, since for reasons of allowing users to easily extend our code and add 
 * new encryption schemes, we want the encryption schemes to be totally separate from the {@code GarbledGate}s. 
 * (See <i>Garbling * Schemes </i> by Mihir Bellare, Viet Tung Hoang, and Phillip Rogaway for their discussion on garbling schemes as
 * an entity in their own right). Therefore, we create the specialized {code {@link MinimizeAESSetKeyGarbledBooleanCircuitUtil} and
 * {@code MinimizeAESSetKeyGarbledGate} to allow us to minimize the number of setKey operations while still in general decoupling 
 * garbling encryption schemes from the gates and circuits. </p>
 * The only difference of this class from {@code StandardGarbledBooleanCircuituUtil} is that it uses {@code 
 * {@link MinimizeAESSetKeyGarbledGate}}s instead of {@code StandardGarbledGate}s. All of the major differences that we discussed take 
 * place in {@link MinimizeAESSetKeyGarbledGate}.<p> 
 * Note that currently only the constructor and not the verify method minimizes AES set key calls.
 * 
 * @author Steven Goldfeder
 * 
 */
class MinimizeAESSetKeyGarbledBooleanCircuitUtil extends StandardGarbledBooleanCircuitUtil {

	private AES aes;
	
	/**
	 * Constructs a garbled circuit utility using {@link AES128MultiKeyEncryption} while minimizing the number of setKey operations performed.
	 * @param aes to use in the computations.
	 * @param random A source of randomness.
	 */
	MinimizeAESSetKeyGarbledBooleanCircuitUtil(AES aes, SecureRandom random) {
		this.random = random;
		this.aes = aes;
		 
		// This will be passed to the gates and used for decryption and (for now) verifying. 
		// Eventually, verifying will also minimize setKey operations and use aes directly.
	    mes = new AES128MultiKeyEncryption(aes);
	}
	
	/**
	 * Default constructor. Uses CryptoPpAES and SecureRandom objects.
	 */
	MinimizeAESSetKeyGarbledBooleanCircuitUtil(){
		this(new CryptoPpAES(), new SecureRandom());
	}
	
	/**
	 * Creates a MinimizeAESSetKeyGarbledGate.
	 * @param ungarbledGate to garble.
	 * @param garbledTablesHolder to fill with the garbled table.
	 * @return the created gate.
	 */
	protected GarbledGate createGate(Gate ungarbledGate, BasicGarbledTablesHolder garbledTablesHolder) {
		return new MinimizeAESSetKeyGarbledGate(ungarbledGate, mes, aes, garbledTablesHolder);
		
	}
}
