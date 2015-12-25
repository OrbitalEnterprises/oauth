package enterprises.orbital.auth;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;

import org.scribe.builder.ServiceBuilder;
import org.scribe.builder.api.TwitterApi;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.model.Verifier;
import org.scribe.oauth.OAuthService;

import com.google.gson.Gson;
import com.google.gson.JsonParser;

/**
 * Handle the callback portion of Twitter auth.
 */
public class TwitterCallbackHandler {
  private static final Logger log = Logger.getLogger(TwitterCallbackHandler.class.getName());

  public static String doGet(String twitterApiKey, String twitterApiSecret, String standardRedirect, HttpServletRequest req) throws IOException {
    // Construct the service to use for verification.
    OAuthService service = new ServiceBuilder().provider(TwitterApi.Authenticate.class).apiKey(twitterApiKey).apiSecret(twitterApiSecret).build();

    Token requestToken = null;
    String caller = standardRedirect;
    try {
      // Retrieve the request token from before. This will throw an exception if we can't find it.
      requestToken = (Token) req.getSession().getAttribute("twitter_req_token");

      // Exchange for access token
      Verifier v = new Verifier(req.getParameter("oauth_verifier"));
      Token accessToken = service.getAccessToken(requestToken, v);

      // Attempt to retrieve credentials.
      OAuthRequest request = new OAuthRequest(Verb.GET, "https://api.twitter.com/1.1/account/verify_credentials.json");
      service.signRequest(accessToken, request);
      Response response = request.send();
      if (!response.isSuccessful()) throw new IOException("credential request was not successful!");

      // Save whether a user is already signed in. If so, then we may be changing an association for a screen name.
      UserAccount existing = AuthUtil.getCurrentUser(req);

      // Two cases to handle here:
      // 1) the credentials match an existing user for auth source "twitter". If so, then we mark this user as logged in from twitter.
      // 2) the credentials don't match an existing user. In this case, we need to create the user for the first time.
      String screenName = (new Gson()).fromJson((new JsonParser()).parse(response.getBody()).getAsJsonObject().get("screen_name"), String.class);
      UserAuthSource sourceVal = AuthUtil.getBySourceScreenname("twitter", screenName);
      if (sourceVal != null) {
        // Already exists
        if (existing != null) {
          // User already signed in so change the associated to the current user. There may also be a redirect we should prefer.
          sourceVal.updateAccount(existing);
          if (req.getSession().getAttribute(AuthUtil.ADDAUTH_REDIRECT_SESSION_VAR) != null) {
            caller = (String) req.getSession().getAttribute(AuthUtil.ADDAUTH_REDIRECT_SESSION_VAR);
            req.getSession().removeAttribute(AuthUtil.ADDAUTH_REDIRECT_SESSION_VAR);
          }
        } else {
          // Otherwise, sign in as usual.
          AuthUtil.signOn(req, sourceVal.getOwner(), sourceVal);
        }
      } else {
        // New user unless already signed in, in which case it's a new association.
        UserAccount newUser = existing == null ? AuthUtil.createNewUserAccount(false) : existing;
        sourceVal = AuthUtil.createSource(newUser, "twitter", screenName, response.getBody());
        if (existing != null) {
          // For existing users, there may be a redirect we need to handle.
          if (req.getSession().getAttribute(AuthUtil.ADDAUTH_REDIRECT_SESSION_VAR) != null) {
            caller = (String) req.getSession().getAttribute(AuthUtil.ADDAUTH_REDIRECT_SESSION_VAR);
            req.getSession().removeAttribute(AuthUtil.ADDAUTH_REDIRECT_SESSION_VAR);
          }
        } else {
          // Otherwise, new user needs to sign in.
          AuthUtil.signOn(req, newUser, sourceVal);
        }
      }

    } catch (Exception e) {
      log.log(Level.WARNING, "Failed twitter authentication with error: ", e);
      caller = null;
    }

    return caller;
  }

}
