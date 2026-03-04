package micheal65536.vienna.apiserver.routes;

import micheal65536.vienna.apiserver.routing.Request;
import micheal65536.vienna.apiserver.routing.Response;
import micheal65536.vienna.apiserver.routing.Router;
import micheal65536.vienna.apiserver.utils.AccountUtils;
import micheal65536.vienna.apiserver.utils.EarthApiResponse;
import micheal65536.vienna.apiserver.utils.MapBuilder;
import micheal65536.vienna.db.EarthDB;
import micheal65536.vienna.db.model.global.Accounts;
import org.jetbrains.annotations.NotNull;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

public final class SigninRouter extends Router {
    private final EarthDB earthDB;
    private static final ConcurrentHashMap<String, SessionInfo> activeSessions = new ConcurrentHashMap<>();
    private static final SecureRandom secureRandom = new SecureRandom();
    private static final long SESSION_TIMEOUT_MS = TimeUnit.HOURS.toMillis(24); // 24 hour timeout

    private static final class SessionInfo {
        final String userId;
        final long creationTime;

        SessionInfo(String userId) {
            this.userId = userId;
            this.creationTime = System.currentTimeMillis();
        }

        boolean isExpired() {
            return System.currentTimeMillis() - this.creationTime > SESSION_TIMEOUT_MS;
        }
    }

    public SigninRouter(@NotNull EarthDB earthDB) {
        this.earthDB = earthDB;
        this.addHandler(
                new Route.Builder(Request.Method.POST, "/player/profile/signin")
                        .addHeaderParameter("sessionId", "Session-Id")
                        .build(),
                request -> {
                    record SigninRequest(String sessionTicket) {
                    }
                    SigninRequest signinRequest = request.getBodyAsJson(SigninRequest.class);

                    String[] parts = signinRequest.sessionTicket.split("-", 2);
                    if (parts.length != 2) {
                        return Response.badRequest();
                    }

                    String userId = parts[0];
                    if (!userId.matches("^[0-9A-F]{16}$")) {
                        return Response.badRequest();
                    }

                    // Check credentials - validate session ticket against database
                    String validationResult = validateCredentials(signinRequest.sessionTicket, userId);
                    if (validationResult != null) {
                        if (validationResult.equals("LOCKED")) {
                            return Response.status(423).body("Account locked due to too many failed attempts").build();
                        } else if (validationResult.equals("NOT_FOUND")) {
                            return Response.notFound().body("User not found").build();
                        } else if (validationResult.equals("INVALID_TICKET")) {
                            return Response.unauthorized().body("Invalid session ticket").build();
                        } else if (validationResult.equals("SUSPENDED")) {
                            return Response.forbidden().body("Account suspended").build();
                        } else if (validationResult.equals("BANNED")) {
                            return Response.forbidden().body("Account banned").build();
                        } else {
                            return Response.unauthorized().build();
                        }
                    }

                    // Generate secure session token
                    String token = generateSecureSessionToken(userId);

                    return Response.okFromJson(new EarthApiResponse<>(new MapBuilder<>()
                            .put("basePath", "/auth")
                            .put("authenticationToken", token)
                            .put("clientProperties", new HashMap<>())
                            .put("mixedReality", null)
                            .put("mrToken", null)
                            .put("streams", null)
                            .put("tokens", new HashMap<>())
                            .put("updates", new HashMap<>())
                            .getMap()), EarthApiResponse.class);
                }
        );
    }

    /**
     * Validates credentials against the database
     * Returns null if valid, otherwise returns error reason
     */
    private String validateCredentials(String sessionTicket, String userId) {
        try {
            // 1. Check if the userId exists in your user database
            EarthDB.Query getAccountQuery = AccountUtils.getAccountByUserId(userId);
            var results = earthDB.executeBlocking(getAccountQuery, 5000);

            Accounts.Account account = (Accounts.Account) results.extra("account");
            if (account == null) {
                return "NOT_FOUND";
            }

            // 2. Check if the account is locked due to failed attempts
            if (AccountUtils.isAccountLocked(account)) {
                return "LOCKED";
            }

            // 3. Check if the account is active/banned
            switch (account.status) {
                case SUSPENDED:
                    return "SUSPENDED";
                case BANNED:
                    return "BANNED";
                case PENDING_VERIFICATION:
                    return "PENDING_VERIFICATION";
                case ACTIVE:
                    // Continue with validation
                    break;
            }

            // 4. Validate the session ticket against stored credentials
            if (!AccountUtils.isSessionTicketValid(account, sessionTicket)) {
                // Increment failed attempts and lock if necessary
                AccountUtils.lockAccount(account);
                EarthDB.Query saveAccountQuery = AccountUtils.saveAccount(userId, account);
                earthDB.executeBlocking(saveAccountQuery, 5000);

                return "INVALID_TICKET";
            }

            // 5. Reset failed attempts on successful validation
            AccountUtils.resetFailedAttempts(account);
            EarthDB.Query saveAccountQuery = AccountUtils.saveAccount(userId, account);
            earthDB.executeBlocking(saveAccountQuery, 5000);

            // 6. Verify any additional security requirements
            // (Add any additional checks here, such as IP restrictions, device verification, etc.)

            return null; // Success
        } catch (Exception e) {
            // Log error and return generic error
            System.err.println("Error validating credentials: " + e.getMessage());
            return "SERVER_ERROR";
        }
    }

    /**
     * Generates a cryptographically secure session token
     */
    private String generateSecureSessionToken(String userId) {
        // Generate 32 random bytes (256 bits)
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);

        // Create token: base64(random bytes) + "." + userId + "." + timestamp
        String randomPart = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
        long timestamp = System.currentTimeMillis();

        String token = String.format("%s.%s.%d", randomPart, userId, timestamp);

        // Store session info for validation
        activeSessions.put(token, new SessionInfo(userId));

        // Clean up expired sessions periodically
        cleanupExpiredSessions();

        return token;
    }

    /**
     * Validates a session token and returns the associated user ID if valid
     */
    public static String validateSessionToken(String token) {
        if (token == null || token.trim().isEmpty()) {
            return null;
        }

        SessionInfo sessionInfo = activeSessions.get(token);
        if (sessionInfo == null || sessionInfo.isExpired()) {
            if (sessionInfo != null) {
                activeSessions.remove(token);
            }
            return null;
        }

        return sessionInfo.userId;
    }

    /**
     * Removes expired sessions from the active sessions map
     */
    private void cleanupExpiredSessions() {
        // Only cleanup every 100 calls to avoid performance impact
        if (secureRandom.nextInt(100) == 0) {
            activeSessions.entrySet().removeIf(entry -> entry.getValue().isExpired());
        }
    }
}