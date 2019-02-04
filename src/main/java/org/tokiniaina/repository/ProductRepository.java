package org.tokiniaina.repository;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import org.tokiniaina.model.Product;

@RepositoryRestResource
public interface ProductRepository  extends MongoRepository<Product,String> {
}
