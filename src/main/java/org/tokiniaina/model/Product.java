package org.tokiniaina.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;

@NoArgsConstructor
@AllArgsConstructor
@ToString
@Data
@Document
public class Product {
    @Id
    private String id;
    private String name;
    private double price;
    @DBRef
    private Category category;
}

