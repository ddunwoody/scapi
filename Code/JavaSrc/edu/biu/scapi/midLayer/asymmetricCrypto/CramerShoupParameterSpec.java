/**
 * 
 */
package edu.biu.scapi.midLayer.asymmetricCrypto;

import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;


/**
 * This class holds parameters needed to initialize an instance of the Cramer-Shoup encryption algorithm.<p>
 * Since Cramer-Shoup is based on a Dlog Group and on a Cryptographic Hash, parameters needed to initialize those underlying parameters are an essential part of this class.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class CramerShoupParameterSpec implements AlgorithmParameterSpec {
	//Cramer-Shoup algo needs a source of randomness to be able to work.
	SecureRandom random;
	//Parameters to initialize the Dlog Group used by Cramer-Shoup
	//Do we want to hold the group params as a variable of type GroupParams or AlgorithmParameterSpec
	AlgorithmParameterSpec groupParams;

	public CramerShoupParameterSpec(SecureRandom random, AlgorithmParameterSpec groupParams) {
		this.random = random;
		this.groupParams = groupParams;
	}
	
	public SecureRandom getSecureRandom(){
		return random;
	}
	public AlgorithmParameterSpec getDlogGroupParams(){
		return groupParams;
	}
}
