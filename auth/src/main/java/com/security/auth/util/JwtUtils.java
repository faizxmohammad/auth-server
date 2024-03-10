package com.security.auth.util;

import com.security.auth.constants.ErrorMessages;
import com.security.auth.constants.ErrorResponseCodes;
import com.security.auth.dto.Status;
import com.security.auth.exceptions.AuthException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.time.DateUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.util.StringUtils;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;


@Slf4j
public class JwtUtils {
    private JwtUtils() {
    }

    private static final String ISSUER = "TGM";
    private static final SecretKey secretKey = Jwts.SIG.HS256.key().build();

    public static boolean validateToken(String jwtToken) {
        return parseToken(jwtToken).isPresent();
    }

    public static Optional<String> getUsernameFromToken(String jwtToken) {
        var claimsOptional = parseToken(jwtToken);
        return claimsOptional.map(Claims::getSubject);

        /*
         *  The above code looks like this:
         *  if(claimsOptional.isPresent()){
         *      return Optional.of(claimsOptional.get().getSubject());
         *   }
         *   return  Optional.empty();
         */
    }

    /**
     * Parse the jwt token to get the payload from it
     *
     * @param jwtToken
     * @return
     */
    private static Optional<Claims> parseToken(String jwtToken) {
        var jwtParser = Jwts.parser().verifyWith(secretKey).build();
        try {
            return Optional.of(jwtParser.parseSignedClaims(jwtToken).getPayload());

        } catch (JwtException ex) {
            log.info("Exception occurred while parsing and getting the payload from the jwt token:{}", ex.getMessage());
        } catch (Exception ex) {
            log.info("Unexpected Exception occurred while parsing and getting the payload from the jwt token:{}", ex.getMessage());
        }
        return Optional.empty();
    }

    // Validates if the jwt token is expired or not
    public static boolean isTokenExpired(String token) {
        var jwtTokenoptional = extractJwtToken(token);

        // if extracted token is empty throw unauthorized exception.
        if (jwtTokenoptional.isEmpty()) {
            log.error("Invalid auth token provided: {}. After extracting the token provided the result was:{}", token, jwtTokenoptional);
            throw new AuthException(ErrorMessages.UNAUTHORIZED, ErrorResponseCodes.UNAUTHORIZED, Status.UNAUTHORIZED);
        }
        return extractExpiration(jwtTokenoptional.get()).before(new Date());

    }

    // gets the expiration claim from the jwt token
    private static Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // A generic method to extract required claims from the jwt token
    private static <T> T extractClaim(String token, Function<Claims, T> claimsResolvers) {
        var claimsOptional = parseToken(token);
        if (claimsOptional.isPresent()) {
            return claimsResolvers.apply(claimsOptional.get());
        }
        throw new IllegalStateException("Invalid jwt token");

    }

    public static String generateToken(String username) {

        var currentDate = new Date();
        var expirationDate = DateUtils.addHours(currentDate, 10);
        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .issuer(ISSUER)
                .subject(username)
                .signWith(secretKey)
                .issuedAt(currentDate)
                .expiration(expirationDate)
                .compact();
    }

    public static Optional<String> extractJwtToken(String authHeader) {
        if (StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer ")) {
            return Optional.of(authHeader.substring(7));
        }
        return Optional.empty();
    }
}
