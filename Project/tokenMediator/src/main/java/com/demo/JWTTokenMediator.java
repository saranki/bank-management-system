package com.demo;

import org.apache.commons.codec.binary.Base64;
import org.apache.synapse.MessageContext;
import org.apache.synapse.mediators.AbstractMediator;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JWTTokenMediator extends AbstractMediator {

	private static final Logger log = LoggerFactory.getLogger(JWTTokenMediator.class);
	private static final String CLAIMS = "http://wso2.org/claims/role";
	private static final String PROPERTY = "role";
	private static String role;
	private String jwtHeader;

	private static String retrieveRole(String accountRequestInfo) {
		String splitString = accountRequestInfo.split("\\.")[1];
		Base64 base64 = new Base64();
		try {
			String decodedString = new String(base64.decode(splitString.getBytes()));
			JSONParser parser = new JSONParser();
			JSONObject requestInfo = (JSONObject) parser.parse(decodedString);

			if (requestInfo.containsKey(CLAIMS)) {
				role = requestInfo.get(CLAIMS).toString();
				return role;
			} else {
				if (log.isDebugEnabled())
					log.error("Role is not available!");
			}
		} catch (ParseException e) {
			log.error("Error in passing Account-Request-Information " + e.toString());
		}
		return null;
	}

	public boolean mediate(MessageContext context) {
		 String jwtValue = getJWTHeader();
		 String retrievedRole = retrieveRole(jwtValue);
		 if(retrievedRole == null) {
			 context.setProperty(PROPERTY, jwtValue);
		 return false;
		 }
		 context.setProperty(PROPERTY, retrievedRole);

		return true;
	}

	public String getJWTHeader() {
		return jwtHeader;
	}

	public void setJWTHeader(String jwtHeader) {
		this.jwtHeader = jwtHeader;
	}
}
