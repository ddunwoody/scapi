package edu.biu.scapi.primitives.prg;

import java.security.spec.AlgorithmParameterSpec;


import javax.crypto.SecretKey;

import edu.biu.scapi.exceptions.UnInitializedException;

/** 
 * This class implements some common functionality of PRG.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public abstract class PseudorandomGeneratorAbs implements PseudorandomGenerator {
	
	protected SecretKey secretKey = null;			//secret key
	protected AlgorithmParameterSpec params = null; //algorithm parameters
	protected boolean isInitialized = false;		//until init is called set to false.

	public void init(SecretKey secretKey) {

		//init the key. Further initialization should be implemented in the derived concrete class.
		this.secretKey = secretKey;
		//marks this object as initialized
		isInitialized = true;
	}

	public void init(SecretKey secretKey, AlgorithmParameterSpec params) {

		//init the parameters. Further initialization should be implemented in the derived concrete class.
		this.secretKey = secretKey;
		this.params = params;
		//marks this object as initialized
		isInitialized = true;
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