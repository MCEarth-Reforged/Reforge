package micheal65536.vienna.db.model.global;

import org.jetbrains.annotations.NotNull;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

public final class Accounts
{
	@NotNull
	public final Map<String, Account> accounts;

	public Accounts()
	{
		this.accounts = new HashMap<>();
	}

	public static final class Account
	{
		@NotNull
		public String userId;
		@NotNull
		public String username;
		@NotNull
		public String email;
		@NotNull
		public String passwordHash;
		@NotNull
		public AccountStatus status;
		@NotNull
		public Instant createdAt;
		@NotNull
		public Instant lastLoginAt;
		@NotNull
		public Map<String, String> sessionTickets; // ticketId -> timestamp
		public int failedLoginAttempts;
		@NotNull
		public Instant lockedUntil;

		public Account()
		{
			this.status = AccountStatus.ACTIVE;
			this.createdAt = Instant.now();
			this.lastLoginAt = Instant.now();
			this.sessionTickets = new HashMap<>();
			this.failedLoginAttempts = 0;
			this.lockedUntil = Instant.EPOCH;
		}
	}

	public enum AccountStatus
	{
		ACTIVE,
		SUSPENDED,
		BANNED,
		PENDING_VERIFICATION
	}
}
