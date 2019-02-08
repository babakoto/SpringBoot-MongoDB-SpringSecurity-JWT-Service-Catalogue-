package org.tokiniaina.security;

public interface SecurityParam {
    String JWT_HEADER_NAME ="Authorization";
    String SECRET = "e.tokiniaina";
    long EXPIRATION= 10*24*3600*1000;
    String HEADER_PREFIX="Baerer ";
}
