package org.security.muralla.service;

import org.security.muralla.model.base.OAuthConsumer;

public interface ConsumerService {
	public OAuthConsumer getConsumer(String id) throws Exception;

	public OAuthConsumer getConsumerByName(String name) throws Exception;
	
	public void saveConsumer(OAuthConsumer consumer);
}
