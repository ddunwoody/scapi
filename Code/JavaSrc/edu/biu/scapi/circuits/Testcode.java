/**
* This file is part of SCAPI.
* SCAPI is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
* SCAPI is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
* You should have received a copy of the GNU General Public License along with SCAPI.  If not, see <http://www.gnu.org/licenses/>.
*
* Any publication and/or code referring to and/or based on SCAPI must contain an appropriate citation to SCAPI, including a reference to http://crypto.cs.biu.ac.il/SCAPI.
*
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
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
