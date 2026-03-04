package micheal65536.vienna.apiserver.utils;

import micheal65536.vienna.db.EarthDB;
import micheal65536.vienna.db.model.global.Accounts;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.concurrent.TimeUnit;

public final class AccountUtils
{
	private static final SecureRandom secureRandom = new SecureRandom();
	private static final int MAX_FAILED_ATTEMPTS = 5;
	private static final long LOCKOUT_DURATION_MS = TimeUnit.MINUTES.toMillis(15);
	private static final long SESSION_TICKET_VALIDITY_MS = TimeUnit.HOURS.toMillis(1);

	/**
	 * Hashes a password with a random salt using SHA-256
	 */
	@NotNull
	public static String hashPassword(@NotNull String password)
	{
		try
		{
			// Generate random salt
			byte[] salt = new byte[16];
			secureRandom.nextBytes(salt);
			
			// Hash password with salt
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			digest.update(salt);
			byte[] hashedBytes = digest.digest(password.getBytes());
			
			// Combine salt and hash: salt:hash (both hex encoded)
			String saltHex = HexFormat.of().formatHex(salt);
			String hashHex = HexFormat.of().formatHex(hashedBytes);
			
			return saltHex + ":" + hashHex;
		}
		catch (NoSuchAlgorithmException e)
		{
			throw new RuntimeException("Failed to hash password", e);
		}
	}

	/**
	 * Verifies a password against a hash
	 */
	public static boolean verifyPassword(@NotNull String password, @NotNull String hashedPassword)
	{
		try
		{
			String[] parts = hashedPassword.split(":");
			if (parts.length != 2)
			{
				return false;
			}
			
			String saltHex = parts[0];
			String storedHashHex = parts[1];
			
			// Recreate hash with stored salt
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] salt = HexFormat.of().parseHex(saltHex);
			digest.update(salt);
			byte[] computedHashBytes = digest.digest(password.getBytes());
			String computedHashHex = HexFormat.of().formatHex(computedHashBytes);
			
			return storedHashHex.equals(computedHashHex);
		}
		catch (NoSuchAlgorithmException | IllegalArgumentException e)
		{
			return false;
		}
	}

	/**
	 * Generates a secure session ticket
	 */
	@NotNull
	public static String generateSessionTicket()
	{
		byte[] randomBytes = new byte[32];
		secureRandom.nextBytes(randomBytes);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
	}

	/**
	 * Validates a session ticket and checks if it's still valid
	 */
	public static boolean isSessionTicketValid(@NotNull Accounts.Account account, @NotNull String ticketId)
	{
		String timestampStr = account.sessionTickets.get(ticketId);
		if (timestampStr == null)
		{
			return false;
		}
		
		try
		{
			long timestamp = Long.parseLong(timestampStr);
			return System.currentTimeMillis() - timestamp < SESSION_TICKET_VALIDITY_MS;
		}
		catch (NumberFormatException e)
		{
			return false;
		}
	}

	/**
	 * Checks if an account is currently locked due to failed login attempts
	 */
	public static boolean isAccountLocked(@NotNull Accounts.Account account)
	{
		return account.failedLoginAttempts >= MAX_FAILED_ATTEMPTS && 
			   Instant.now().isBefore(account.lockedUntil);
	}

	/**
	 * Locks an account after too many failed attempts
	 */
	public static void lockAccount(@NotNull Accounts.Account account)
	{
		account.failedLoginAttempts++;
		if (account.failedLoginAttempts >= MAX_FAILED_ATTEMPTS)
		{
			account.lockedUntil = Instant.now().plusMillis(LOCKOUT_DURATION_MS);
		}
	}

	/**
	 * Resets failed login attempts after successful login
	 */
	public static void resetFailedAttempts(@NotNull Accounts.Account account)
	{
		account.failedLoginAttempts = 0;
		account.lockedUntil = Instant.EPOCH;
		account.lastLoginAt = Instant.now();
	}

	/**
	 * Creates a database query to get an account by user ID
	 */
	@NotNull
	public static EarthDB.Query getAccountByUserId(@NotNull String userId)
	{
		EarthDB.Query query = new EarthDB.Query(true);
		query.get("accounts", "global", Accounts.class);
		query.then(results ->
		{
			Accounts accounts = (Accounts) results.get("accounts").value();
			Accounts.Account account = accounts.accounts.get(userId);
			query.extra("account", account);
			return query;
		});
		return query;
	}

	/**
	 * Creates a database query to get an account by username
	 */
	@NotNull
	public static EarthDB.Query getAccountByUsername(@NotNull String username)
	{
		EarthDB.Query query = new EarthDB.Query(true);
		query.get("accounts", "global", Accounts.class);
		query.then(results ->
		{
			Accounts accounts = (Accounts) results.get("accounts").value();
			Accounts.Account foundAccount = null;
			for (Accounts.Account account : accounts.accounts.values())
			{
				if (account.username.equalsIgnoreCase(username))
				{
					foundAccount = account;
					break;
				}
			}
			query.extra("account", foundAccount);
			return query;
		});
		return query;
	}

	/**
	 * Creates a database query to save an account
	 */
	@NotNull
	public static EarthDB.Query saveAccount(@NotNull String userId, @NotNull Accounts.Account account)
	{
		EarthDB.Query query = new EarthDB.Query(true);
		query.get("accounts", "global", Accounts.class);
		query.then(results ->
		{
			Accounts accounts = (Accounts) results.get("accounts").value();
			accounts.accounts.put(userId, account);
			EarthDB.Query updateQuery = new EarthDB.Query(true);
			updateQuery.update("accounts", "global", accounts);
			return updateQuery;
		});
		return query;
	}
}
