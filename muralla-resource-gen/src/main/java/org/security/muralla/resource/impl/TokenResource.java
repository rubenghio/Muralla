package org.security.muralla.resource.impl;

import javax.inject.Inject;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.UriInfo;

import org.apache.log4j.Logger;
import org.security.muralla.model.base.AccessTokenRegistry;
import org.security.muralla.model.base.AuthenticatedTokenRegistry;
import org.security.muralla.model.base.OAuthConsumer;
import org.security.muralla.model.base.OAuthRequest;
import org.security.muralla.model.base.OAuthResponse;
import org.security.muralla.model.base.RequestTokenRegistry;
import org.security.muralla.model.utils.OAuthUtils;
import org.security.muralla.service.TokenService;

@Path("/oauth")
public class TokenResource {
	private static final Logger LOG = Logger.getLogger(TokenResource.class);
	private static final String SIGNATURE_VALIDATION_ERROR = "Signatures do not match!!!";

	@Inject
	private TokenService tokenService;
	@Context
	private UriInfo uriInfo;
	private static final String POST = "POST";

	@POST
	@Path("/request_token")
	@Produces(MediaType.TEXT_PLAIN)
	public Response requestToken(
			@HeaderParam("Authorization") String authorization) {
		try {
			// Check if consumer exists
			OAuthRequest request = new OAuthRequest(POST, uriInfo
					.getRequestUri().toASCIIString(), authorization);
			OAuthConsumer consumer = tokenService.getConsumer(request
					.getValue(OAuthUtils.OAUTH_CONSUMER_KEY));

			String sign = OAuthUtils.getSignature(request.getBaseString(),
					consumer.getSecret(), OAuthUtils.EMPTY);

			// Check if message was altered
			if (!sign.equals(request.getValue(OAuthUtils.OAUTH_SIGNATURE))) {
				return Response.status(Status.BAD_REQUEST)
						.entity(SIGNATURE_VALIDATION_ERROR).build();
			}

			// Check if same token was already requested
			tokenService.checkDuplicateRequest(
					request.getValue(OAuthUtils.OAUTH_TIMESTAMP),
					request.getValue(OAuthUtils.OAUTH_NONCE));

			// Generate request token
			OAuthResponse response = new OAuthResponse();
			response.addParameter(OAuthUtils.OAUTH_CALLBACK_CONFIRMED,
					Boolean.TRUE.toString());

			// Save request token generated in the database
			RequestTokenRegistry tokenRegistry = new RequestTokenRegistry(
					request.getValue(OAuthUtils.OAUTH_NONCE),
					request.getValue(OAuthUtils.OAUTH_TIMESTAMP),
					request.getValue(OAuthUtils.OAUTH_CALLBACK),
					request.getValue(OAuthUtils.OAUTH_SIGNATURE),
					request.getValue(OAuthUtils.OAUTH_VERSION),
					request.getValue(OAuthUtils.OAUTH_SIGNATURE_METHOD),
					request.getValue(OAuthUtils.OAUTH_CONSUMER_KEY),
					response.getToken(), response.getTokenSecret());
			tokenService.saveRequestToken(tokenRegistry);

			return Response.ok(response.toString()).build();
		} catch (Exception e) {
			LOG.error(e.getMessage());
			return Response.status(Status.BAD_REQUEST).entity(e.getMessage())
					.build();
		}
	}

	@POST
	@Path("/access_token")
	@Produces(MediaType.TEXT_PLAIN)
	public Response accessToken(
			@HeaderParam("Authorization") String authorization) {
		try {
			OAuthRequest request = new OAuthRequest(POST, uriInfo
					.getRequestUri().toASCIIString(), authorization);
			OAuthConsumer consumer = tokenService.getConsumer(request
					.getValue(OAuthUtils.OAUTH_CONSUMER_KEY));
			RequestTokenRegistry requestTokenRegistry = tokenService
					.getRequestToken(request.getValue(OAuthUtils.OAUTH_TOKEN));
			AuthenticatedTokenRegistry authenticatedTokenRegistry = tokenService
					.getAuthenticatedToken(request
							.getValue(OAuthUtils.OAUTH_TOKEN));

			String sign = OAuthUtils
					.getSignature(request.getBaseString(),
							consumer.getSecret(),
							requestTokenRegistry.getTokenSecret());

			// Check if message was altered
			if (!sign.equals(request.getValue(OAuthUtils.OAUTH_SIGNATURE))) {
				return Response.status(Status.BAD_REQUEST)
						.entity(SIGNATURE_VALIDATION_ERROR).build();
			}

			// Create Access Token
			OAuthResponse response = new OAuthResponse();
			response.addParameter(OAuthUtils.MEMBER_ID,
					authenticatedTokenRegistry.getUsername());

			// Save access token generated in the database
			AccessTokenRegistry accessTokenRegistry = new AccessTokenRegistry(
					request.getValue(OAuthUtils.OAUTH_NONCE),
					request.getValue(OAuthUtils.OAUTH_TIMESTAMP),
					request.getValue(OAuthUtils.OAUTH_VERSION),
					request.getValue(OAuthUtils.OAUTH_SIGNATURE_METHOD),
					request.getValue(OAuthUtils.OAUTH_CONSUMER_KEY),
					request.getValue(OAuthUtils.OAUTH_TOKEN),
					response.getTokenSecret(),
					request.getValue(OAuthUtils.OAUTH_VERIFIER),
					request.getValue(OAuthUtils.OAUTH_SIGNATURE),
					response.getToken());
			tokenService.saveAccessToken(accessTokenRegistry);

			return Response.ok(response.toString()).build();
		} catch (Exception e) {
			LOG.error(e.getMessage());
			return Response.status(Status.BAD_REQUEST).entity(e.getMessage())
					.build();
		}
	}
}
