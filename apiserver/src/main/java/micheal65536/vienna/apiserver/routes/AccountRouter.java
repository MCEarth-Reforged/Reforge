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
import java.util.HexFormat;
import java.util.regex.Pattern;

public final class AccountRouter extends Router
{
	private final EarthDB earthDB;
	private static final SecureRandom secureRandom = new SecureRandom();
	
	// Username validation: 3-20 characters, alphanumeric and underscores only
	private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_]{3,20}$");
	
	// Email validation (basic)
	private static final Pattern EMAIL_PATTERN = Pattern.compile("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");
	
	// Password validation: at least 8 characters, contains letters and numbers
	private static final Pattern PASSWORD_PATTERN = Pattern.compile("^(?=.*[A-Za-z])(?=.*\\d)[A-Za-z\\d@$!%*#?&]{8,}$");

	public AccountRouter(@NotNull EarthDB earthDB)
	{
		this.earthDB = earthDB;
		
		this.addHandler(
			new Route.Builder(Request.Method.POST, "/account/register")
					.build(),
			this::handleRegister
		);
		
		this.addHandler(
			new Route.Builder(Request.Method.POST, "/account/create-session-ticket")
					.build(),
			this::handleCreateSessionTicket
		);
	}

	private Response handleRegister(@NotNull Request request)
	{
		record RegisterRequest(String username, String email, String password) {}
		RegisterRequest registerRequest = request.getBodyAsJson(RegisterRequest.class);
		
		// Validate input
		String validationError = validateRegistrationInput(registerRequest.username, registerRequest.email, registerRequest.password);
		if (validationError != null)
		{
			return Response.badRequest().body(validationError).build();
		}
		
		try
		{
			// Check if username already exists
			if (isUsernameTaken(registerRequest.username))
			{
				return Response.conflict().body("Username already taken").build();
			}
			
			// Check if email already exists
			if (isEmailTaken(registerRequest.email))
			{
				return Response.conflict().body("Email already registered").build();
			}
			
			// Generate unique user ID
			String userId = generateUserId();
			
			// Create new account
			Accounts.Account newAccount = new Accounts.Account();
			newAccount.userId = userId;
			newAccount.username = registerRequest.username;
			newAccount.email = registerRequest.email;
			newAccount.passwordHash = AccountUtils.hashPassword(registerRequest.password);
			newAccount.status = Accounts.AccountStatus.ACTIVE;
			
			// Save account to database
			EarthDB.Query saveQuery = AccountUtils.saveAccount(userId, newAccount);
			earthDB.executeBlocking(saveQuery, 5000);
			
			// Return success response with user ID
			return Response.okFromJson(new EarthApiResponse<>(new MapBuilder<>()
					.put("userId", userId)
					.put("username", newAccount.username)
					.put("message", "Account created successfully")
					.getMap()), EarthApiResponse.class);
		}
		catch (Exception e)
		{
			return Response.internalServerError().body("Failed to create account").build();
		}
	}

	private Response handleCreateSessionTicket(@NotNull Request request)
	{
		record SessionTicketRequest(String userId, String password) {}
		SessionTicketRequest ticketRequest = request.getBodyAsJson(SessionTicketRequest.class);
		
		if (ticketRequest.userId == null || ticketRequest.password == null)
		{
			return Response.badRequest().body("userId and password are required").build();
		}
		
		try
		{
			// Get account from database
			EarthDB.Query getAccountQuery = AccountUtils.getAccountByUserId(ticketRequest.userId);
			var results = earthDB.executeBlocking(getAccountQuery, 5000);
			
			Accounts.Account account = (Accounts.Account) results.extra("account");
			if (account == null)
			{
				return Response.notFound().body("Account not found").build();
			}
			
			// Check if account is locked
			if (AccountUtils.isAccountLocked(account))
			{
				return Response.status(423).body("Account locked due to too many failed attempts").build();
			}
			
			// Check account status
			if (account.status != Accounts.AccountStatus.ACTIVE)
			{
				return Response.forbidden().body("Account is not active").build();
			}
			
			// Verify password
			if (!AccountUtils.verifyPassword(ticketRequest.password, account.passwordHash))
			{
				// Increment failed attempts
				AccountUtils.lockAccount(account);
				EarthDB.Query saveQuery = AccountUtils.saveAccount(ticketRequest.userId, account);
				earthDB.executeBlocking(saveQuery, 5000);
				
				return Response.unauthorized().body("Invalid password").build();
			}
			
			// Reset failed attempts on successful login
			AccountUtils.resetFailedAttempts(account);
			
			// Generate session ticket
			String sessionTicket = AccountUtils.generateSessionTicket();
			account.sessionTickets.put(sessionTicket, String.valueOf(System.currentTimeMillis()));
			
			// Save updated account
			EarthDB.Query saveQuery = AccountUtils.saveAccount(ticketRequest.userId, account);
			earthDB.executeBlocking(saveQuery, 5000);
			
			// Return session ticket
			return Response.okFromJson(new EarthApiResponse<>(new MapBuilder<>()
					.put("sessionTicket", ticketRequest.userId + "-" + sessionTicket)
					.put("userId", ticketRequest.userId)
					.put("username", account.username)
					.put("message", "Session ticket created successfully")
					.getMap()), EarthApiResponse.class);
		}
		catch (Exception e)
		{
			return Response.internalServerError().body("Failed to create session ticket").build();
		}
	}

	private String validateRegistrationInput(String username, String email, String password)
	{
		if (username == null || username.trim().isEmpty())
		{
			return "Username is required";
		}
		
		if (!USERNAME_PATTERN.matcher(username).matches())
		{
			return "Username must be 3-20 characters and contain only letters, numbers, and underscores";
		}
		
		if (email == null || email.trim().isEmpty())
		{
			return "Email is required";
		}
		
		if (!EMAIL_PATTERN.matcher(email).matches())
		{
			return "Invalid email format";
		}
		
		if (password == null || password.trim().isEmpty())
		{
			return "Password is required";
		}
		
		if (!PASSWORD_PATTERN.matcher(password).matches())
		{
			return "Password must be at least 8 characters and contain both letters and numbers";
		}
		
		return null; // No validation errors
	}

	private boolean isUsernameTaken(String username)
	{
		try
		{
			EarthDB.Query getAccountQuery = AccountUtils.getAccountByUsername(username);
			var results = earthDB.executeBlocking(getAccountQuery, 5000);
			return results.extra("account") != null;
		}
		catch (Exception e)
		{
			return false; // Assume not taken on error
		}
	}

	private boolean isEmailTaken(String email)
	{
		try
		{
			EarthDB.Query getAccountsQuery = new EarthDB.Query(true);
			getAccountsQuery.get("accounts", "global", Accounts.class);
			var results = earthDB.executeBlocking(getAccountsQuery, 5000);
			
			Accounts accounts = (Accounts) results.extra("accounts");
			if (accounts == null)
			{
				return false;
			}
			
			return accounts.accounts.values().stream()
					.anyMatch(account -> account.email.equalsIgnoreCase(email));
		}
		catch (Exception e)
		{
			return false; // Assume not taken on error
		}
	}

	private String generateUserId()
	{
		// Generate 16-character hexadecimal user ID
		byte[] bytes = new byte[8];
		secureRandom.nextBytes(bytes);
		return HexFormat.of().formatHex(bytes).toUpperCase();
	}
}
