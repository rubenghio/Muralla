package org.security.muralla.resource.impl;

import java.util.Random;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.apache.log4j.Logger;
import org.security.muralla.model.base.AuthenticatedTokenRegistry;
import org.security.muralla.model.base.RequestTokenRegistry;
import org.security.muralla.service.TokenService;

import py.com.familiar.arandu.security.context.UserContext;

@Path("/oauth")
public class TokenResource {
	private static final Logger LOG = Logger.getLogger(TokenResource.class);
	@Inject
	private UserContext userContext;

	@Inject
	private TokenService tokenService;

	@GET
	@Produces(MediaType.TEXT_PLAIN)
	@Path("/authorize")
	public Response authenticate(@QueryParam("oauth_token") String token) {
		try {
			RequestTokenRegistry requestTokenRegistry = tokenService
					.getRequestToken(token);
			// Generate verifier
			Random rand = new Random();
			int min = 100000000;
			int max = 999999999;
			int randomNum = rand.nextInt((max - min) + 1) + min;

			AuthenticatedTokenRegistry authenticatedTokenRegistry = new AuthenticatedTokenRegistry(
					requestTokenRegistry.getConsumerKey(),
					userContext.getName(), requestTokenRegistry.getTimestamp(),
					requestTokenRegistry.getNonce(), Integer.valueOf(randomNum)
							.toString(), token);

			tokenService.saveAuthenticatedToken(authenticatedTokenRegistry);
			return Response.ok(Integer.valueOf(randomNum).toString()).build();
		} catch (Exception e) {
			LOG.error(e.getMessage());
			return Response.status(Status.BAD_REQUEST).entity(e.getMessage())
					.build();
		}
	}
}
