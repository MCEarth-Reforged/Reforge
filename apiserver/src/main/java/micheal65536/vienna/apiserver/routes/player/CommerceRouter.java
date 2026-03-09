package micheal65536.vienna.apiserver.routes.player;

import org.jetbrains.annotations.NotNull;

import micheal65536.vienna.apiserver.routing.Request;
import micheal65536.vienna.apiserver.routing.Response;
import micheal65536.vienna.apiserver.routing.Router;
import micheal65536.vienna.apiserver.routing.ServerErrorException;
import micheal65536.vienna.apiserver.utils.EarthApiResponse;
import micheal65536.vienna.apiserver.utils.MapBuilder;
import micheal65536.vienna.db.DatabaseException;
import micheal65536.vienna.db.EarthDB;
import micheal65536.vienna.db.model.player.Inventory;
import micheal65536.vienna.db.model.player.Profile;

import java.util.HashMap;

public class CommerceRouter extends Router
{
	public CommerceRouter(@NotNull EarthDB earthDB)
	{
		this.addHandler(new Route.Builder(Request.Method.POST, "/commerce/purchaseV2").build(), request ->
		{
			record PurchaseRequest(
					@NotNull String productId,
					int quantity,
					int expectedPrice
			)
			{
			}
			
			PurchaseRequest purchaseRequest = request.getBodyAsJson(PurchaseRequest.class);
			if (purchaseRequest.quantity < 1)
			{
				return Response.badRequest();
			}
			if (purchaseRequest.expectedPrice < 0)
			{
				return Response.badRequest();
			}

			try
			{
				String playerId = request.getContextData("playerId");
				
				// Calculate total cost (for now, use expectedPrice as the actual price)
				int totalCost = purchaseRequest.expectedPrice * purchaseRequest.quantity;
				
				EarthDB.Results results = new EarthDB.Query(true)
						.get("profile", playerId, Profile.class)
						.get("inventory", playerId, Inventory.class)
						.then(results1 ->
						{
							Profile profile = (Profile) results1.get("profile").value();
							Inventory inventory = (Inventory) results1.get("inventory").value();

							// Check if player has enough rubies
							if (!profile.rubies.spend(totalCost))
							{
								return new EarthDB.Query(false); // Failed due to insufficient rubies
							}

							// Add purchased items to inventory
							// For now, we'll use productId as the itemId. In a real implementation, 
							// you'd want to look up the actual item from a product catalog
							inventory.addItems(purchaseRequest.productId, purchaseRequest.quantity);

							return new EarthDB.Query(true)
									.update("profile", playerId, profile)
									.update("inventory", playerId, inventory);
						})
						.execute(earthDB);

				if (results.get("profile").value() == null)
				{
					return Response.badRequest(); // Purchase failed (likely insufficient rubies)
				}

				// Return success response
				HashMap<String, Object> purchaseResponse = new MapBuilder<>()
						.put("productId", purchaseRequest.productId)
						.put("quantity", purchaseRequest.quantity)
						.put("totalCost", totalCost)
						.put("transactionId", java.util.UUID.randomUUID().toString())
						.getMap();

				return Response.okFromJson(new EarthApiResponse<>(purchaseResponse, new EarthApiResponse.Updates(results)), EarthApiResponse.class);
			}
			catch (DatabaseException exception)
			{
				throw new ServerErrorException(exception);
			}
		});
	}
}
