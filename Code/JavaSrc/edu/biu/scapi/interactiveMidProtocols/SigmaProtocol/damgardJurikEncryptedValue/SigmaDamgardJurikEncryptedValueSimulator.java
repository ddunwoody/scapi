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
package edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.damgardJurikEncryptedValue;

import java.math.BigInteger;
import java.security.SecureRandom;

import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.SigmaSimulator;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.damgardJurikEncryptedZero.SigmaDJEncryptedZeroInput;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.damgardJurikEncryptedZero.SigmaDamgardJurikEncryptedZeroSimulator;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaProtocolInput;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaSimulatorOutput;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.DamgardJurikPublicKey;
import edu.biu.scapi.midLayer.ciphertext.BigIntegerCiphertext;
import edu.biu.scapi.midLayer.plaintext.BigIntegerPlainText;

/**
 * Concrete implementation of Sigma Simulator.
 * 
 * This implementation simulates the case that party who encrypted a value x proves that it indeed encrypted x.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaDamgardJurikEncryptedValueSimulator implements SigmaSimulator{

	/*	
	  This class uses an instance of SigmaDamgardJurikEncryptedZeroSimulator with:
	  	•	Common input: (n,c’) where c’=c*(1+n)^(-x) mod N'
	*/
	
	private SigmaDamgardJurikEncryptedZeroSimulator djSim; // Underlying SigmaDamgardJurikEncryptedZeroSimulator to use.
	private int lengthParameter; 						   // Used in converting the input to the underlying input.
	
	/**
	 * Constructor that gets the soundness parameter, length parameter and SecureRandom.
	 * @param t Soundness parameter in BITS.
	 * @param lengthParameter length parameter in BITS.
	 * @param random
	 */
	public SigmaDamgardJurikEncryptedValueSimulator(int t, int lengthParameter, SecureRandom random) {
		
		//Creates the underlying sigmaDamgardJurik object with the given parameters.
		djSim = new SigmaDamgardJurikEncryptedZeroSimulator(t, lengthParameter, random);
		this.lengthParameter = lengthParameter;
	}
	
	/**
	 * Default constructor that chooses default values for the parameters.
	 */
	public SigmaDamgardJurikEncryptedValueSimulator() {
		lengthParameter = 1;
		//Creates the underlying sigmaDamgardJurik object with default parameters.
		djSim = new SigmaDamgardJurikEncryptedZeroSimulator(80, lengthParameter, new SecureRandom());
	}
	
	/**
	 * Constructor that gets a simulator and sets it.
	 * In getSimulator function in SigmaDamgardJurikEncryptedValueProver, the prover needs to create an instance of this class.
	 * The problem is that the prover does not know which t and random to give, since they are values of the underlying 
	 * SigmaDamgardJurikencryptedZeroProver that the prover holds.
	 * Using this constructor, the (DJEncryptedValue) prover can get the DJEncryptedZero simulator from the underlying (DJEncryptedZero) 
	 * prover and use it to create this object.
	 * 
	 * @param simulator MUST be an instance of SigmaDamgardJurikEncryptedZeroSimulator.
	 * @throws IllegalArgumentException if the given simulator is not an instance of SigmaDamgardJurikEncryptedZeroSimulator.
	 */
	SigmaDamgardJurikEncryptedValueSimulator(SigmaSimulator simulator) {
		
		if (!(simulator instanceof SigmaDamgardJurikEncryptedZeroSimulator)){
			throw new IllegalArgumentException("The given simulator is not an instance of SigmaDamgardJurikEncryptedZeroSimulator");
		}
		//Sets the given object to the underlying SigmaDamgardJurikEncryptedZeroSimulator.
		djSim = (SigmaDamgardJurikEncryptedZeroSimulator) simulator;
	}
	
	/**
	 * Returns the soundness parameter for this Sigma protocol.
	 * @return t soundness parameter
	 */
	public int getSoundness(){
		return djSim.getSoundness();
	}
	
	/**
	 * Computes the simulator computation.
	 * @param input MUST be an instance of SigmaDJEncryptedValueInput.
	 * @param challenge
	 * @return the output of the computation - (a, e, z).
	 * @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	 * @throws IllegalArgumentException if input is not the expected.
	 */
	public SigmaSimulatorOutput simulate(SigmaProtocolInput in, byte[] challenge) throws CheatAttemptException{
		SigmaDJEncryptedZeroInput underlyingInput = checkAndCreateUnderlyingInput(in);
		
		//Delegates the computation to the underlying SigmaDJEncryptedZeroSimulator.
		return djSim.simulate(underlyingInput, challenge); 
				
	}
	
	/**
	 * Computes the simulator computation.
	 * @param input MUST be an instance of SigmaDJEncryptedValueInput.
	 * @return the output of the computation - (a, e, z).
	 * @throws IllegalArgumentException if input is not the expected.
	 */
	public SigmaSimulatorOutput simulate(SigmaProtocolInput in){
		SigmaDJEncryptedZeroInput underlyingInput = checkAndCreateUnderlyingInput(in);
		
		//Delegates the computation to the underlying SigmaDJEncryptedZeroSimulator.
		return djSim.simulate(underlyingInput); 
				
	}
	
	/**
	 * Converts the given input to an input object for the underlying simulator.
	 * @param in MUST be an instance of SigmaDJEncryptedValueInput.
	 * @return SigmaDJEncryptedZeroInput the converted input.
	 */
	private SigmaDJEncryptedZeroInput checkAndCreateUnderlyingInput(
			SigmaProtocolInput in) {
		if (!(in instanceof SigmaDJEncryptedValueInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaDJEncryptedValueInput");
		}
		SigmaDJEncryptedValueInput input = (SigmaDJEncryptedValueInput) in;
		
		//Get public key, cipher and plaintext.
		DamgardJurikPublicKey pubKey = input.getPublicKey();
		BigIntegerPlainText plaintext = input.getPlaintext();
		BigIntegerCiphertext cipher = input.getCiphertext();
		
		//Convert the cipher c to c' = c*(1+n)^(-x)
		BigInteger n = pubKey.getModulus();
		BigInteger nPlusOne = n.add(BigInteger.ONE);
		
		//calculate N' = n^(s+1).
		BigInteger NTag = n.pow(lengthParameter + 1);
		
		//Calculate (n+1)^(-x)
		BigInteger minusX = plaintext.getX().negate();
		BigInteger multVal = nPlusOne.modPow(minusX, NTag);
		
		//Calculate the ciphertext for DamgardJurikEncryptedZero - c*(n+1)^(-x).
		BigInteger newCipher = cipher.getCipher().multiply(multVal).mod(NTag);
		BigIntegerCiphertext cipherTag = new BigIntegerCiphertext(newCipher);
		
		//Create an input object to the underlying sigmaDamgardJurik simulator.
		SigmaDJEncryptedZeroInput underlyingInput = new SigmaDJEncryptedZeroInput(pubKey, cipherTag);
		return underlyingInput;
	}
}
