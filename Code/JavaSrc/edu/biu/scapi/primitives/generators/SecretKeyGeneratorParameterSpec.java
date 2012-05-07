package edu.biu.scapi.primitives.generators;

import java.security.spec.AlgorithmParameterSpec;

/**
 * This class is the parameters for the secret key generation.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SecretKeyGeneratorParameterSpec implements AlgorithmParameterSpec{

	private int keySize = 0;				//the required key size
	private String algorithmName = null;	//the algorithm name of the required key
	
	/** 
	 * Constructor that gets the size and the algorithm name and sets them.
	 * @param keySize the required key size
	 * @param name the algorithm name of the key
	 */
	public SecretKeyGeneratorParameterSpec(int keySize, String name){
		//sets the parameters
		this.keySize = keySize;
		algorithmName = name;
	}
	
	/**
	 * @return the required key size
	 */
	public int getKeySize(){
		return keySize;
	}
	
	/**
	 * @return algorithm name of the key
	 */
	public String getAlgorithmName(){
		return algorithmName;
	}
}
