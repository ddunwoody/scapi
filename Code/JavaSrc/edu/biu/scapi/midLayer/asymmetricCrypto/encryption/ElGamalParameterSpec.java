package edu.biu.scapi.midLayer.asymmetricCrypto.encryption;

import java.security.spec.AlgorithmParameterSpec;


/**
 * Parameter for ElGamal initialization.
 * ElGamal relies on DlogGroup and it's initialization parameters contains the parameters for the dlog's initialization.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ElGamalParameterSpec implements AlgorithmParameterSpec {

	private String dlogName;
	private String provider;
	private AlgorithmParameterSpec params;
	
	/**
	 * Constructor that gets the dlog name parameters that required for ElGamal initialization
	 * @param dlogName dlog group type
	 * @param params dlog group description
	 */
	public ElGamalParameterSpec(String dlogName, AlgorithmParameterSpec params){
		this.dlogName = dlogName;
		this.params = params;
	}
	
	/**
	 * Constructor that gets the dlog name parameters that required for ElGamal initialization
	 * @param dlogName dlog group type
	 * @param params dlog group description
	 */
	public ElGamalParameterSpec(String dlogName, String provider, AlgorithmParameterSpec params){
		this.dlogName = dlogName;
		this.provider = provider;
		this.params = params;
	}
	
	/**
	 * @return the dlog name
	 */
	public String getDlogName(){
		return dlogName;
	}
	
	/**
	 * @return the provider name
	 */
	public String getProviderName(){
		return provider;
	}
	
	/**
	 * 
	 * @return DlogGroup description
	 */
	public AlgorithmParameterSpec getGroupParams(){
		return params;
	}
}
