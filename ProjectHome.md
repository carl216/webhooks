This project provides an implementation of [javax.crypto.SecretKey](http://java.sun.com/javase/6/docs/api/javax/crypto/SecretKey.html), which can be used as the seed for HMAC-MD5 message authentication.  HMAC-MD5 authentication is what Google Code uses to authenticate its web hook messages sent to projects after each commit to subversion.

Use of this SecretKey implementation allows you to verify your received web hook messages in Java.  A complete example of how to use this SecretKey implementation is provided below.

```
package com.google.code.webhooks.examples;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Hex;

import com.google.code.webhooks.GoogleCodeSecretKey;

/**
 * Servlet implementation class for Servlet: MessageAuth
 * 
 * This servlet simply accepts Google Code web hook messages and authenticates them.  The 
 * results of the authentication are simply written back to the requester (Google Code) along with a text
 * file written on the server (hosting this servlet).  Obviously, you'll want to do much more useful
 * things based on the results of the authentication.
 * 
 * Two external libs are required for this example to work:
 * 	I'm using Apache Commons codec library for hex encoding; feel free to replace it with any hex encoder you like
 * 	Of course, you need to add the gc_webhooks.jar to your classpath in order to have the GoogleCodeSecretKey class available
 */
 public final class MessageAuth extends javax.servlet.http.HttpServlet implements javax.servlet.Servlet {
   static final long serialVersionUID = 1L;

   // The javax.crypto.SecretKey used to seed the HMAC-MD5 message
   final private SecretKey secret;
   
    /* (non-Java-doc)
	 * @see javax.servlet.http.HttpServlet#HttpServlet()
	 */
	public MessageAuth() throws IOException {
		super();
		// Assumption: Your Google Code project's secret key is stored in the
		// file referenced in the File() constructor below
		secret = new GoogleCodeSecretKey(new File("/etc/googlecode/myproj/secret.key"));
	}   	
		
	/* (non-Java-doc)
	 * @see javax.servlet.http.HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
                String payload = new String();
		// Read the contents of the raw POST data sent in the request and store it
		BufferedReader r = request.getReader();
		String line;
		while((line = r.readLine()) != null)
			payload = payload.concat(line + "\n");
		r.close();
		payload = payload.trim();

		// The expected hash result, as sent in the request headers by Google
		String expectedHash = request.getHeader("Google-Code-Project-Hosting-Hook-Hmac");

		// Validate the request and write the results; you'll want to do something
		// much more exciting based on the results of the validate() method
		String result;
		if(validate(expectedHash, payload))
			result = "Message authenticated successfully!";
		else
			result = "Message authentication failed!";
		response.getWriter().write(result);
		BufferedWriter w = new BufferedWriter(new FileWriter("/tmp/auth.results", true));
		w.write(new Date().toString() + ": " + result + "\n");
		w.close();
	}
	
	/**
	 * Compute the payload's HMAC-MD5 hash value and compare it to the expected value received in request headers from Google
	 * @return True if the payload's hash value is equal to the expected value stored as a member object of this instance
	 */
	static private boolean validate(String expectedHash, String payload) {
		if(expectedHash == null)
			return false;
		
		try {
			Mac mac = Mac.getInstance("HmacMD5");
			mac.init(secret);
			// I'm using Apache Commons codec lib to do the hex encoding; use whatever hex encoder lib you like
			return expectedHash.equals(new String(Hex.encodeHex(mac.doFinal(payload.getBytes(Charset.forName("UTF-8"))))));
		} catch(KeyException e) {
			e.printStackTrace(); // Presumably, this stack trace will be dumped to your J2EE container's log files
			return false;
		} catch(NoSuchAlgorithmException e) {
			e.printStackTrace();
			return false;
		}
	}
}
```