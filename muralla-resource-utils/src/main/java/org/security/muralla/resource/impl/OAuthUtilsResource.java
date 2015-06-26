package org.security.muralla.resource.impl;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.UUID;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.apache.log4j.Logger;
import org.security.muralla.model.base.OAuthConsumer;
import org.security.muralla.model.base.OAuthRequest;
import org.security.muralla.model.base.RequestTokenRegistry;
import org.security.muralla.model.utils.OAuthUtils;
import org.security.muralla.service.ConsumerService;
import org.security.muralla.service.TokenService;

@Path("/oauthUtils")
public class OAuthUtilsResource {
	private static final Logger LOG = Logger
			.getLogger(OAuthUtilsResource.class);

	@Inject
	private TokenService tokenService;
	@Inject
	private ConsumerService consumerService;

	@POST
	@Path("/token_signature")
	@Produces(MediaType.TEXT_PLAIN)
	@Consumes(MediaType.APPLICATION_JSON)
	public Response requestTokenSignature(
			@HeaderParam("Authorization") String authorization,
			SignParameter signParameter) {
		try {
			if (authorization == null || signParameter == null
					|| signParameter.getUrl() == null
					|| signParameter.getMethod() == null
					|| signParameter.getAccess() == null) {
				throw new Exception(
						"Header 'Authorization' and Body parameters 'url', 'method' and 'access' are required!");
			}

			OAuthRequest request = new OAuthRequest(signParameter.getMethod(),
					signParameter.getUrl(), authorization);
			OAuthConsumer consumer = consumerService.getConsumer(request
					.getValue(OAuthUtils.OAUTH_CONSUMER_KEY));
			String tokenSecret = OAuthUtils.EMPTY;
			if (signParameter.getAccess()) {
				RequestTokenRegistry requestTokenRegistry = tokenService
						.getRequestToken(request
								.getValue(OAuthUtils.OAUTH_TOKEN));
				tokenSecret = requestTokenRegistry.getTokenSecret();
			}
			return Response.ok(
					OAuthUtils.getSignature(request.getBaseString(),
							consumer.getSecret(), tokenSecret)).build();
		} catch (Exception e) {
			LOG.error(e.getMessage());
			return Response.status(Status.BAD_REQUEST).entity(e.getMessage())
					.build();
		}
	}

	@POST
	@Path("/consumer")
	@Produces(MediaType.APPLICATION_JSON)
	@Consumes(MediaType.APPLICATION_JSON)
	public Response saveConsumer(OAuthConsumer consumer) {
		try {
			consumerService.getConsumerByName(consumer.getName());
			return Response
					.status(Status.BAD_REQUEST)
					.entity("Consumer " + consumer.getName()
							+ " already exists!!!").build();
		} catch (Exception e) {
			LOG.warn(e.getMessage());
		}

		try {
			String secret = URLEncoder.encode(UUID.randomUUID().toString()
					.replaceAll("-", ""), OAuthUtils.ENCODING);
			String consumerKey = URLEncoder.encode(UUID.randomUUID().toString()
					.replaceAll("-", ""), OAuthUtils.ENCODING);
			OAuthConsumer consumerNew = new OAuthConsumer();
			consumerNew.setConsumerKey(consumerKey);
			consumerNew.setName(consumer.getName());
			consumerNew.setSecret(secret);
			consumerService.saveConsumer(consumerNew);
			return Response.ok(consumerNew).build();
		} catch (UnsupportedEncodingException e) {
			LOG.error(e.getMessage());
			return Response.status(Status.BAD_REQUEST).entity(e.getMessage())
					.build();
		}
	}
}
