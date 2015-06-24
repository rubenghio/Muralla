package org.security.muralla.model.base;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.message.BasicNameValuePair;
import org.security.muralla.model.utils.OAuthUtils;

public class OAuthRequest {
	private static final String OAUTH_AUTHORIZATION = "OAuth";
	private static final String CREDENTIALS_ERROR = "Invalid token credentials";
	private String method;
	private String url;
	private Map<String, String> paramMap = new LinkedHashMap<String, String>();
	private List<NameValuePair> paramList;

	public OAuthRequest(String method, String url, String request)
			throws Exception {
		if (request == null || request.isEmpty()
				|| !request.contains(OAUTH_AUTHORIZATION)) {
			throw new Exception(CREDENTIALS_ERROR);
		}
		this.method = method;
		this.url = url;
		String params = request.replace(OAUTH_AUTHORIZATION, "")
				.replace("\"", "").trim();
		this.paramMap = getMap(params);
		this.paramList = getList(paramMap);
	}

	public List<NameValuePair> getParamList() {
		return paramList;
	}

	public String getValue(String paramName) throws Exception {
		String value = paramMap.get(paramName);
		if (value == null) {
			throw new Exception("Parameter '" + paramName
					+ "' does not exist!!!");
		}
		return value;
	}

	private Map<String, String> getMap(String request) throws Exception {
		List<String> paramList = Arrays.asList(request.split("\\s*,\\s*"));
		Map<String, String> map = new LinkedHashMap<String, String>();
		for (String param : paramList) {
			String[] paramCouple = param.split("=");
			String key = paramCouple[0];
			String value = URLDecoder.decode(paramCouple[1].replace("\"", ""),
					OAuthUtils.ENCODING);
			map.put(key, value);
		}
		return map;
	}

	private List<NameValuePair> getList(Map<String, String> map)
			throws Exception {
		List<NameValuePair> syncList = Collections
				.synchronizedList(new ArrayList<NameValuePair>());
		for (String key : map.keySet()) {
			syncList.add(new BasicNameValuePair(key, map.get(key)));
		}

		Collections.sort(syncList, new Comparator<NameValuePair>() {
			public int compare(NameValuePair synchronizedListOne,
					NameValuePair synchronizedListTwo) {
				return ((NameValuePair) synchronizedListOne)
						.getName()
						.compareTo(
								((NameValuePair) synchronizedListTwo).getName());
			}
		});

		return syncList;
	}

	/*
	 * 'oauth_signature' parameter is beign removed for signature comparison
	 */
	private List<NameValuePair> getParamListForSignature() {
		List<NameValuePair> signList = new LinkedList<NameValuePair>(paramList);
		Iterator<NameValuePair> it = signList.iterator();
		while (it.hasNext()) {
			NameValuePair pair = it.next();
			if (OAuthUtils.OAUTH_SIGNATURE.equals(pair.getName())) {
				it.remove();
				break;
			}
		}
		return signList;
	}

	public String getBaseString() throws UnsupportedEncodingException {
		return URLEncoder.encode(method, OAuthUtils.ENCODING)
				+ OAuthUtils.AMP
				+ URLEncoder.encode(url, OAuthUtils.ENCODING)
				+ OAuthUtils.AMP
				+ URLEncoder.encode(URLEncodedUtils.format(
						getParamListForSignature(), OAuthUtils.ENCODING),
						OAuthUtils.ENCODING);
	}
}
