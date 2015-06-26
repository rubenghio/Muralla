package org.security.muralla.service.impl;

import java.util.List;

import javax.annotation.security.PermitAll;
import javax.ejb.Stateless;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;

import org.security.muralla.entity.OAuthConsumerEntity;
import org.security.muralla.model.base.OAuthConsumer;
import org.security.muralla.service.ConsumerService;

@Stateless
@PermitAll
public class ConsumerServiceBean implements ConsumerService {
	@PersistenceContext(unitName = "muralla-security-oauth")
	private EntityManager em;

	@Override
	public OAuthConsumer getConsumer(String id) throws Exception {
		OAuthConsumer consumer = em.find(OAuthConsumerEntity.class, id);
		if (consumer == null) {
			throw new Exception("Client does not exists!!!");
		}
		return consumer;
	}

	@Override
	public void saveConsumer(OAuthConsumer consumer) {
		em.persist(new OAuthConsumerEntity(consumer));
	}

	@Override
	@SuppressWarnings("unchecked")
	public OAuthConsumer getConsumerByName(String name) throws Exception {
		Query query = em
				.createQuery("from OAuthConsumerEntity where name = :name");
		query.setParameter("name", name);
		List<OAuthConsumerEntity> list = query.getResultList();
		if (list == null || list.isEmpty()) {
			throw new Exception("Consumer with name '" + name
					+ "' does not exist!!!");
		}
		return (OAuthConsumer) list.get(0);
	}
}
