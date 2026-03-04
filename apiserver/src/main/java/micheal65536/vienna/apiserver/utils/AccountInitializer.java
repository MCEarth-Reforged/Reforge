package micheal65536.vienna.apiserver.utils;

import micheal65536.vienna.db.EarthDB;
import micheal65536.vienna.db.model.global.Accounts;

import org.jetbrains.annotations.NotNull;

public final class AccountInitializer
{
	/**
	 * Initializes the accounts collection in the database if it doesn't exist
	 * This is a utility method for database setup
	 */
	public static void initializeAccounts(@NotNull EarthDB earthDB)
	{
		try
		{
			// Check if accounts collection exists
			EarthDB.Query getAccountsQuery = new EarthDB.Query(true);
			getAccountsQuery.get("accounts", "global", Accounts.class);
			var results = earthDB.executeBlocking(getAccountsQuery, 5000);
			
			Accounts accounts = (Accounts) results.extra("accounts");
			if (accounts == null)
			{
				// Create empty accounts collection
				accounts = new Accounts();
				
				// Save to database
				EarthDB.Query saveQuery = new EarthDB.Query(true);
				saveQuery.update("accounts", "global", accounts);
				earthDB.executeBlocking(saveQuery, 5000);
				
				System.out.println("Initialized accounts collection in database");
			}
		}
		catch (Exception e)
		{
			System.err.println("Error initializing accounts collection: " + e.getMessage());
		}
	}
}
