package org.security.muralla.resource.impl;

import java.io.Serializable;

public class SignParameter implements Serializable {
	private static final long serialVersionUID = -6541929548494815302L;

	private String url;
	private String method;
	private Boolean access;

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	public String getMethod() {
		return method;
	}

	public void setMethod(String method) {
		this.method = method;
	}

	public Boolean getAccess() {
		return access;
	}

	public void setAccess(Boolean access) {
		this.access = access;
	}
}
