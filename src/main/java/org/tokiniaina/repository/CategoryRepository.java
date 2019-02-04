package org.tokiniaina.repository;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import org.tokiniaina.model.Category;

@RepositoryRestResource
public interface CategoryRepository extends MongoRepository<Category,String> {
}
