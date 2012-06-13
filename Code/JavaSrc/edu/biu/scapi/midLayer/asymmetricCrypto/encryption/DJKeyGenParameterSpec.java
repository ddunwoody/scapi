package edu.biu.scapi.midLayer.asymmetricCrypto.encryption;

import java.security.spec.AlgorithmParameterSpec;

/**
 * Parameters for DamgardJurik key generation.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class DJKeyGenParameterSpec implements AlgorithmParameterSpec {

	private int modulusLength;
	private int certainty;
	
	public DJKeyGenParameterSpec(int modulusLength, int certainty){
		this.modulusLength = modulusLength;
		this.certainty = certainty;
	}

	public int getModulusLength() {
		return modulusLength;
	}

	public int getCertainty() {
		return certainty;
	}
	
	
}
