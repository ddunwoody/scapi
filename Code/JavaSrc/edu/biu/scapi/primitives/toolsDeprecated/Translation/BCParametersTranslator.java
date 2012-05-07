
package edu.biu.scapi.tools.Translation;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.RC5ParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.RC5Parameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;

/** 
 * @author LabTest
 */
public class BCParametersTranslator {
	/** 
	 */
	//create the singleton object
	private final static BCParametersTranslator parametersTranslator = new BCParametersTranslator();
	
	/**
	 * Empty constructor should be private since this class is singleton and we want to prevent user creation
	 * of this class
	 */
	private BCParametersTranslator(){};

	/** 
	 * @return
	 */
	public static BCParametersTranslator getInstance() {

		//return the singleton
		return parametersTranslator;
	}

	/** 
	 * Translates the key and the parameters into a CipherParameter of BC. If one of the arguments is null then 
	 * pass to one of the other two translateParameter functions.
	 * @param key - the KeySpec to translate to CipherParameters of BC
	 * @param param - The additional AlgorithmParametersSpec to tranform including the key to relevan CipherParameter
	 */
	public CipherParameters translateParameter(KeySpec key, AlgorithmParameterSpec param) {
		
		//if one of the arguments is null than pass to one of the other 2 translateParameter functions
		if(key==null){
			return translateParameter(param);
		}
		else if(param==null){
			return translateParameter(key);
		}
		else{
		
			//get the cipher parameter with the key.
			CipherParameters keyParam = translateParameter(key);
			
			if(param instanceof IvParameterSpec){
				//pass the key and the iv
				return new ParametersWithIV(keyParam , ((IvParameterSpec)param).getIV());
			}
		}
		
		return null;
		
	}

	/** 
	 * This function translates a secret key into a KeyParameter or other asymmetric key parameters. 
	 * @param key - the key
	 * @return KeyParameter - this is used in may of the bc BlockCipher and bc StreamCipher.
	 *         AssymetricKeyParameter - for trapdoor permutation and asymmetric encryption
	 */
	public CipherParameters translateParameter(KeySpec key) {
		
		if (key instanceof SecretKeySpec){
			
			//return the related KeyParameter of BC 
			return new KeyParameter(((SecretKeySpec)key).getEncoded()); 
		}
		else if(key instanceof RSAPrivateKeySpec){
			
			//cast the rsa key
			RSAPrivateKeySpec rsaKey = (RSAPrivateKeySpec)key;
			return new RSAKeyParameters(true, rsaKey.getModulus(), rsaKey.getPrivateExponent());
		}
		else if(key instanceof RSAPublicKeySpec){
			
			//cast the rsa key
			RSAPublicKeySpec rsaKey = (RSAPublicKeySpec)key;
			return new RSAKeyParameters(false, rsaKey.getModulus(), rsaKey.getPublicExponent());
		}
		
		return null;
		
	}

	/** 
	 * @param param
	 * @return
	 */
	public CipherParameters translateParameter(AlgorithmParameterSpec param) {
		
		if(param instanceof RC5ParameterSpec){
			
			RC5ParameterSpec rc5Params = (RC5ParameterSpec)param;
			return new RC5Parameters(rc5Params.getIV(), rc5Params.getRounds());
		}

		
		return null;
		
	}
}