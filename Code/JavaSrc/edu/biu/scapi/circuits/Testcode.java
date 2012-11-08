/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2012 - SCAPI (http://crypto.biu.ac.il/scapi)
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
* 
* We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to
* http://crypto.biu.ac.il/SCAPI.
* 
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
*/

package edu.biu.scapi.circuits;


public class Testcode {

	public static void main(String... args) throws Exception {
/*		SymmetricEnc enc = new ScCBCEncRandomIV(new BcAES(), new BitPadding());
		SecretKey key = enc.generateKey(128);
		try {
			enc.setKey(key);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		Plaintext original = new ByteArrayPlaintext("111".getBytes());
		SymmetricCiphertext cipher = enc.encrypt(original);
		Plaintext plaintext = enc.decrypt(cipher);
		System.out.println(plaintext.equals(original));
*/	
		
	/*CryptographicHash hash = CryptographicHashFactory.getInstance().getObject("SHA-1");
	CryptographicHash hash2 = CryptographicHashFactory.getInstance().getObject("SHA-1");
	byte[] b = new byte[]{1,2,3,4,5,6,7};
	hash.update(b,0,7);
	hash.update(new byte[]{8}, 0, 1);
	byte[] out1 = new byte[20];
	hash.hashFinal(out1, 0);
	for(byte i: out1){
	System.out.print(i);
	}
	System.out.println();
	hash2.update(new byte[]{1,2,3,4,5,6,7,8},0, 8);
	hash2.hashFinal(out1,0);
	for(byte i: out1){
		System.out.print(i);
	}
	System.out.println();
	SecretKey key = new SecretKeySpec(b,"");
	for(byte i :key.getEncoded()){
		System.out.println(i);
	}
	SymmetricCiphertext n*/
		hashTest();
	}
	static void hashTest() throws Exception{
	/*	byte[] b = new byte[]{1,2,3,4,5,6,7,8,9,10,1,2,3,4,5,6,7};
		for(byte i :b){
			System.out.print(i + " ");
		}
		System.out.println();
		HashingMultiKeyEncryption hash = new HashingMultiKeyEncryption();
		hash.setKey(hash.generateMultiKey(hash.generateKey()));
		SymmetricCiphertext c = hash.encrypt(new ByteArrayPlaintext(b));
		for(byte i :c.getBytes()){
			System.out.print(i + " ");
		}
		System.out.println();
		ByteArrayPlaintext bap =(ByteArrayPlaintext) hash.decrypt(c);
		for(byte i :bap.getText()){
			System.out.print(i + " ");
		}
		System.out.println();*/
		//signalTest();

	}
	/*static void signalTest(){
		SecretKey k = new SecretKeySpec(new byte[] {0,1,2,3,76},"");
		System.out.println(StandardGarbledGate.getSignalBit(k));
	}*/
}
