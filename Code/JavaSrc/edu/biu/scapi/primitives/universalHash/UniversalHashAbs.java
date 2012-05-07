package edu.biu.scapi.primitives.universalHash;

import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.SecretKey;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.UnInitializedException;

/** 
 * This class implements some common functionality of perfect universal hash.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public abstract class UniversalHashAbs implements UniversalHash {
	protected AlgorithmParameterSpec params = null;
	protected SecretKey secretKey = null;
	protected boolean isInitialized = false; //until init is called set to false

	
	public void init(SecretKey secretKey) {
		//sets the key
		this.secretKey = secretKey;
		isInitialized = true; //marks this object as initialized
	}
	
	public void init(SecretKey secretKey, AlgorithmParameterSpec params) throws FactoriesException{
		//sets the parameters
		this.params = params;
		this.secretKey = secretKey;
		isInitialized = true; //marks this object as initialized
	}

	public boolean isInitialized(){
		return isInitialized;
	}
	
	public AlgorithmParameterSpec getParams() throws UnInitializedException {
		if (!isInitialized()){
			throw new UnInitializedException();
		}
		return params;
	}
	
}
