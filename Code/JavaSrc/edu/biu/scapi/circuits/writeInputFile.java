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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;

public class writeInputFile {
	public static void main(String... args) throws FileNotFoundException {
		String input = "00000000000100010010001000110011010001000101010101100110011101111000100010011001101010101011101111001100110111011110111011111111";
		String key = "00000000000000010000001000000011000001000000010100000110000001110000100000001001000010100000101100001100000011010000111000001111";
		File f = new File("AESinputs.txt");
		PrintWriter p = new PrintWriter(f);
		p.println(input.length()+ key.length());
		for (int i = 0; i < 128; i++) {
			p.println(i + " " + key.charAt(i));
		}
		for (int i = 0; i < 128; i++) {
			p.println(128 + i + " " + input.charAt(i));
		}
		p.close();
	}
}
