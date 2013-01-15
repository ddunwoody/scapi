/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2012 - SCAPI (http://crypto.biu.ac.il/scapi)
* This file is part of the SCAPI project.
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



package edu.biu.scapi.tools;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Vector;


/**
 * This utility ads SCAPI's license as a header to the all the java files in some folder and in its sub-folders recursively. Needs to be used with caution. 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class LicenseCommentInserter {

		public final static String BASE_PATH_CODE = "C:\\work\\LAST_Project\\SDK\\Code\\C++Src\\JniNtl";
		
		
		public void addCommentToFile(String fileName) throws IOException{
		
			BufferedReader br = new BufferedReader(new FileReader(fileName));
			Vector<String> lines = new Vector<String>();
			String line;
			while((line = br.readLine()) != null){
				lines.add(line);
			}
			br.close();
			
			PrintWriter out = new PrintWriter(fileName);
			out.println("/**");
			out.println("* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%");
			out.println("* ");
			out.println("* Copyright (c) 2012 - SCAPI (http://crypto.biu.ac.il/scapi)");
			out.println("* This file is part of the SCAPI project.");
			out.println("* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.");
			out.println("* "); 
			out.println("* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the \"Software\"),");
			out.println("* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, ");
			out.println("* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:");
			out.println("* "); 
			out.println("* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.");
			out.println("* "); 
			out.println("* THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS");
			out.println("* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,");
			out.println("* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.");
			out.println("* "); 
			out.println("* We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to");
			out.println("* http://crypto.biu.ac.il/SCAPI.");
			out.println("* ");			 
			out.println("* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.");
			out.println("* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%");
			out.println("* "); 
			out.println("*/");
			out.println();
			//for (String lineToPrint : lines){
			for (int i = 0; i < lines.size(); i++){
				out.println(lines.get(i));
			}
			out.flush();
			out.close();
		}
		
		public void addCommentToAllJavaFilesInDirectory(String dirName) throws IOException{
			File dir = new File(dirName);
			File[] allFiles = dir.listFiles();
			for (int i = 0; i < allFiles.length; ++i) {
				if (allFiles[i].isFile()) {
					if(allFiles[i].getName().endsWith(".c") || allFiles[i].getName().endsWith(".h")){
						String path = allFiles[i].getPath();
						String name = allFiles[i].getName(); 
						addCommentToFile(path );
					}
				} else if(allFiles[i].isDirectory()){
					addCommentToAllJavaFilesInDirectory(allFiles[i].toString());
				}
			}
		}
		
		
		/**
		 * @param args
		 */
		public static void main(String[] args) {
			LicenseCommentInserter t = new LicenseCommentInserter();
			try {
				t.addCommentToAllJavaFilesInDirectory(BASE_PATH_CODE);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

	}

	
