/**
 * 
 */
package edu.biu.scapi.midLayer.symmetricCrypto;

/**
 * This class holds any necessary parameters needed for Authentication Encryption.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class AuthEncParameterSpec extends SymEncParameterSpec{
	private SymEncParameterSpec encParams;
	private AuthenticationParameterSpec macParams;
	/**
	 * @param encParams
	 * @param macParams
	 */
	public AuthEncParameterSpec(SymEncParameterSpec encParams,
			AuthenticationParameterSpec macParams) {
		this.encParams = encParams;
		this.macParams = macParams;
	}
	public SymEncParameterSpec getEncParams() {
		return encParams;
	}
	public AuthenticationParameterSpec getMacParams() {
		return macParams;
	}
	
}
