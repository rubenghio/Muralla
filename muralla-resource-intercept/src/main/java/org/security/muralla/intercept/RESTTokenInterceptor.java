package org.security.muralla.intercept;

import java.lang.reflect.Method;
import java.util.List;

import javax.inject.Inject;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;

import org.apache.log4j.Logger;
import org.jboss.resteasy.annotations.interception.ServerInterceptor;
import org.jboss.resteasy.core.Headers;
import org.jboss.resteasy.core.ResourceMethod;
import org.jboss.resteasy.core.ServerResponse;
import org.jboss.resteasy.plugins.interceptors.SecurityInterceptor;
import org.jboss.resteasy.spi.Failure;
import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.interception.PreProcessInterceptor;
import org.security.muralla.model.base.AccessTokenRegistry;
import org.security.muralla.model.base.OAuthConsumer;
import org.security.muralla.model.base.OAuthRequest;
import org.security.muralla.model.utils.OAuthUtils;
import org.security.muralla.service.ConsumerService;
import org.security.muralla.service.TokenService;

@Provider
@ServerInterceptor
public class RESTTokenInterceptor implements PreProcessInterceptor,
		ExceptionMapper<Throwable> {
	private static final String AUTHORIZATION_PROPERTY = "authorization";
	private static final String SIGNATURE_VALIDATION_ERROR = "Signatures do not match!!!";
	private static final ServerResponse ACCESS_DENIED = new ServerResponse(
			"Access denied for this resource", 401, new Headers<Object>());
	private static final ServerResponse SERVER_ERROR = new ServerResponse(
			"INTERNAL SERVER ERROR", 500, new Headers<Object>());
	private final static String AUTH_PRE_KEY = "OAuth";

	@Context
	private UriInfo uriInfo;
	@Inject
	private TokenService tokenService;
	@Inject
	private ConsumerService consumerService;
	private static final Logger LOG = Logger
			.getLogger(SecurityInterceptor.class);

	@Override
	public ServerResponse preProcess(HttpRequest request,
			ResourceMethod methodInvoked) throws Failure,
			WebApplicationException {
		Method method = methodInvoked.getMethod();
		LOG.info("Executing method '" + method.getName() + "'");

		// Get request headers
		final HttpHeaders headers = request.getHttpHeaders();

		// Fetch authorization header
		final List<String> authorization = headers
				.getRequestHeader(AUTHORIZATION_PROPERTY);

		// If no authorization information present; block access
		if (authorization == null || authorization.isEmpty()
				|| authorization.get(0) == null
				|| !authorization.get(0).contains(AUTH_PRE_KEY)) {
			return ACCESS_DENIED;
		}

		String httpMethod = "";
		if (method.isAnnotationPresent(POST.class)) {
			httpMethod = "POST";
		} else if (method.isAnnotationPresent(GET.class)) {
			httpMethod = "GET";
		} else if (method.isAnnotationPresent(PUT.class)) {
			httpMethod = "PUT";
		} else if (method.isAnnotationPresent(DELETE.class)) {
			httpMethod = "DELETE";
		} else {
			LOG.error("HTTP method type does not exist. Methods allow: GET, POST, PUT, DELETE");
			return SERVER_ERROR;
		}

		try {
			OAuthRequest oauthRequest = new OAuthRequest(httpMethod, uriInfo
					.getRequestUri().toASCIIString(), authorization.get(0));
			AccessTokenRegistry accessTokenRegistry = tokenService
					.getAccessToken(oauthRequest
							.getValue(OAuthUtils.OAUTH_TOKEN));
			OAuthConsumer consumer = consumerService.getConsumer(oauthRequest
					.getValue(OAuthUtils.OAUTH_CONSUMER_KEY));

			String sign = OAuthUtils.getSignature(oauthRequest.getBaseString(),
					consumer.getSecret(), accessTokenRegistry.getTokenSecret());

			// Check if message was altered
			if (!sign.equals(oauthRequest.getValue(OAuthUtils.OAUTH_SIGNATURE))) {
				LOG.error(SIGNATURE_VALIDATION_ERROR);
				return SERVER_ERROR;
			}
		} catch (Exception e) {
			LOG.error(e.getMessage());
			return SERVER_ERROR;
		}

		// Return null to continue request processing
		return null;
	}

	@Override
	public Response toResponse(Throwable exception) {
		// TODO Auto-generated method stub
		return null;
	}
}
