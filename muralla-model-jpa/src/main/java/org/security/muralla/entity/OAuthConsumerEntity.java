package org.security.muralla.entity;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

import org.security.muralla.model.base.OAuthConsumer;

@Entity
@Table(name = "oauth_consumer")
public class OAuthConsumerEntity extends OAuthConsumer {
	@Id
	@Column(name = "consumer_key")
	@Override
	public String getConsumerKey() {
		return super.getConsumerKey();
	}

	@Override
	@Column(name = "secret", length = 2048)
	public String getSecret() {
		return super.getSecret();
	}

	@Override
	public String getName() {
		return super.getName();
	}
}
