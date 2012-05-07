package edu.biu.scapi.paddings;

import java.security.spec.AlgorithmParameterSpec;

/**
 * PaddingParameterSpec holds a padding name.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class PaddingParameterSpec implements AlgorithmParameterSpec {

	private String paddingName;
	
	/**
	 * Constructor that gets a padding name and sets it.
	 * @param paddingName
	 */
	public PaddingParameterSpec(String paddingName){
		this.paddingName = paddingName;
	}
	
	/**
	 * 
	 * @return the padding name
	 */
	public String getPaddingName(){
		return paddingName;
	}
}
