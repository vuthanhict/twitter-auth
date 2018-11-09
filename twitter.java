// Step 1: Obtaining a request token

public String twitterConnect() {
	String twitterConsumerSecret = "your_consumer_secret";
	String twitterConsumerKey = "your_consumer_key";

	TwitterConnectionFactory connectionFactory = new TwitterConnectionFactory(twitterConsumerKey, twitterConsumerSecret);
	OAuth1Operations oAuth1Operations = connectionFactory.getOAuthOperations();
	String callbackUrl = "your_callback_url"; // Add callback_url on setting https://apps.twitter.com/app/xxxx
	OAuthToken requestToken = oAuth1Operations.fetchRequestToken(callbackUrl, null);
	String authorizeUrl = oAuth1Operations.buildAuthorizeUrl(requestToken.getValue(), OAuth1Parameters.NONE);
	return authorizeUrl;
}

// Step 2: Redirecting the user

// Step 3: Converting the request token to an access token
public String twitterToken(String pOauthToken, String pOauthVerifier) {

	if (StringUtils.isEmpty(pOauthToken)
			|| StringUtils.isEmpty(pOauthVerifier) {
		return Optional.empty();
	}

	String twitterConsumerSecret = "your_consumer_secret";
	String twitterConsumerKey = "your_consumer_key";

	/*  Converting the request token to an access token */
	String twitter_endpoint = "https://api.twitter.com/oauth/access_token";
	String oauth_signature_method = "HMAC-SHA1";
	String uuid_string = UUID.randomUUID().toString();
	uuid_string = uuid_string.replaceAll("-", "");
	String oauth_nonce = uuid_string;

	// Get the timestamp
	long ts = Calendar.getInstance().getTimeInMillis();
	String oauth_timestamp = (new Long(ts / 1000)).toString();

	String parameter_string = "oauth_consumer_key=" + ""
			+ "&oauth_nonce=" + oauth_nonce
			+ "&oauth_signature_method=" + oauth_signature_method
			+ "&oauth_timestamp=" + oauth_timestamp
			+ "&oauth_token=" + encode(pOauthToken)
			+ "&oauth_version=1.0";

	String signature_base_string = "POST" + "&" + encode(twitter_endpoint) + "&" + encode(parameter_string);

	String oauth_signature = "";
	try {
		oauth_signature = computeSignature(signature_base_string, twitterConsumerSecret + "&");
	} catch (GeneralSecurityException | UnsupportedEncodingException e) {
		System.out.println(e.getMessage());
	}

	String authorization_header_string = "OAuth oauth_consumer_key=\"" + twitterConsumerKey + " \","
			+ "oauth_signature_method=\"" + oauth_signature_method + "\","
			+ "oauth_timestamp=\"" + oauth_timestamp + "\","
			+ "oauth_nonce=\"" + oauth_nonce + "\","
			+ "oauth_version=\"" + "1.0" + "\","
			+ "oauth_signature=\"" + encode(oauth_signature) + "\","
			+ "oauth_token=\"" + encode(pOauthToken) + "\"";

	HttpPost httpPost = new HttpPost(twitter_endpoint);

	httpPost.addHeader("Authorization", authorization_header_string);
	httpPost.addHeader("Content-type", "application/x-www-form-urlencoded");
	try {
		httpPost.setEntity(new StringEntity("oauth_verifier=" + encode(pOauthVerifier), "UTF8"));

		HttpResponse httpResponse = httpClient.execute(httpPost);
		String responseBody = EntityUtils.toString(httpResponse.getEntity(), "UTF-8");
		logger.debug("[Twitter] Body content: {}", responseBody);
		if (httpResponse.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
			
			
			String oauthToken = "";
			String oauthTokenSecret = "";
			String userId = "";
			String ccreenName = "";
			
			StringTokenizer st = new StringTokenizer(responseBody, "&");
			String currentToken;
			while(st.hasMoreTokens()) {
				currentToken = st.nextToken();
				if (currentToken.startsWith("oauth_token=")) {
					oauthToken = currentToken.substring(currentToken.indexOf("=") + 1);
				} else if (currentToken.startsWith("oauth_token_secret=")) {
					oauthTokenSecret = currentToken.substring(currentToken.indexOf("=") + 1);
				} else if (currentToken.startsWith("user_id=")) {
					userId = currentToken.substring(currentToken.indexOf("=") + 1);
				} else if (currentToken.startsWith("screen_name=")) {
					ccreenName = currentToken.substring(currentToken.indexOf("=") + 1);
				} else {
					// Nothing
				}
			}

			if (StringUtils.isEmpty(oauthToken)
					|| StringUtils.isEmpty(oauthTokenSecret)) {
				System.out.println("[Twitter] oauth_token | oauth_token_secret empty.");
				return null;
			}
			return oauthToken;
		} else {
			System.out.println("[Twitter] auth error!");
		}
	} catch (Exception e) {
		logger.error(e.getMessage(), e);
	}

	return null;
}

private static String computeSignature(String baseString, String keyString) throws GeneralSecurityException, UnsupportedEncodingException {
	SecretKey secretKey;

	byte[] keyBytes = keyString.getBytes();
	secretKey = new SecretKeySpec(keyBytes, "HmacSHA1");

	Mac mac = Mac.getInstance("HmacSHA1");
	mac.init(secretKey);

	byte[] text = baseString.getBytes();

	return new String(Base64.encodeBase64(mac.doFinal(text))).trim();
}

private static String encode(String value) {
	String encoded = null;
	try {
		encoded = URLEncoder.encode(value, "UTF-8");
	} catch (UnsupportedEncodingException ignore) {
	}
	StringBuilder buf = new StringBuilder(encoded.length());
	char focus;
	for (int i = 0; i < encoded.length(); i++) {
		focus = encoded.charAt(i);
		if (focus == '*') {
			buf.append("%2A");
		} else if (focus == '+') {
			buf.append("%20");
		} else if (focus == '%' && (i + 1) < encoded.length()
				&& encoded.charAt(i + 1) == '7' && encoded.charAt(i + 2) == 'E') {
			buf.append('~');
			i += 2;
		} else {
			buf.append(focus);
		}
	}
	return buf.toString();
}