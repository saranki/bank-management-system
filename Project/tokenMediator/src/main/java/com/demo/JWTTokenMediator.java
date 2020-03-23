package com.demo;

import java.util.Base64;

import org.apache.synapse.MessageContext;
import org.apache.synapse.mediators.AbstractMediator;
import org.slf4j.LoggerFactory;

import jdk.nashorn.internal.parser.JSONParser;

public class JWTTokenMediator extends AbstractMediator {

	private static final Logger log = LoggerFactory.getLogger(JWTTokenMediator.class);
	private String jwtHeader;
	private static String role;

	private static String retrieveRole(String accountRequestInfo) {
		String[] splitString = accountRequestInfo.split("\\.");
		String base64EncodedBody = splitString[1];

		Base64 base64 = new Base64();
		try {
			String decodedString = new String(base64.decode(base64EncodedBody.getBytes()));
			JSONParser parser = new JSONParser();
			JSONObject accountRequestInfoJson = (JSONObject) parser.parse(decodedString);
			if (accountRequestInfoJson.containsKey("http://wso2.org/claims/role")) {

				role = accountRequestInfoJson.get("http://wso2.org/claims/role").toString();
				return role;
			} else {
				if (log.isDebugEnabled())
					log.error("external id is not available");
			}
		} catch (ParseException e) {
			log.error("Error in passing Account-Request-Information " + e.toString());
		}
		return null;
	}

	public boolean mediate(MessageContext context) {

		context.setProperty("role", retrieveRole(getJWT_HEADER()));

		return true;
	}

	public String getJWT_HEADER() {
		return jwtHeader;
	}

	public void setJWT_HEADER(String jwtHeader) {
		this.jwtHeader = jwtHeader;
	}
}
