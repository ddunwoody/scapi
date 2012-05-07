package edu.biu.scapi.midLayer.signature;

public class RSASignature implements Signature{
	
	private byte[] signature;
	
	public RSASignature(byte[] signature){
		this.signature = signature;
	}
	
	public byte[] getSignatureBytes(){
		return signature;
	}
}
