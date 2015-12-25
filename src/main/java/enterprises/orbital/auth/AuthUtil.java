package enterprises.orbital.auth;

import java.io.IOException;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;

/**
 * Singleton class providing authentication utilities.
 * 
 */
public class AuthUtil {
  /** The session variable holding the UID for the currently signed in user */
  public static final String         UID_SESSION_VAR              = "oe_true_user";
  /** The session variable holding the sign on source for the currently signed in user */
  public static final String         SOURCE_SESSION_VAR           = "oe_auth_source";
  /** The session variable holding the redirect when adding a source for a signed in user */
  public static final String         ADDAUTH_REDIRECT_SESSION_VAR = "oe_addauth_redirect";

  @SuppressWarnings("unused")
  private static final Logger        log                          = Logger.getLogger(AuthUtil.class.getName());

  private static UserAccountProvider uaProvider                   = new UserAccountProvider() {

                                                                    @Override
                                                                    public UserAccount getAccount(String uid) {
                                                                      throw new IllegalStateException();
                                                                    }

                                                                    @Override
                                                                    public UserAuthSource getSource(UserAccount acct, String source) {
                                                                      throw new IllegalStateException();
                                                                    }

                                                                    @Override
                                                                    public void removeSourceIfExists(UserAccount acct, String source) {
                                                                      throw new IllegalStateException();
                                                                    }

                                                                    @Override
                                                                    public UserAuthSource getBySourceScreenname(String source, String screenName) {
                                                                      throw new IllegalStateException();
                                                                    }

                                                                    @Override
                                                                    public UserAuthSource createSource(
                                                                                                       UserAccount newUser,
                                                                                                       String source,
                                                                                                       String screenName,
                                                                                                       String body) {
                                                                      throw new IllegalStateException();
                                                                    }

                                                                    @Override
                                                                    public UserAccount createNewUserAccount(boolean b) {
                                                                      throw new IllegalStateException();
                                                                    }

                                                                  };

  public static void setUserAccountProvider(UserAccountProvider provider) {
    uaProvider = provider;
  }

  public static void prepAuthFlow(HttpServletRequest req) {
    if (getCurrentUser(req) == null) return;
    if (req.getParameter("redirect") != null) {
      req.getSession().setAttribute(ADDAUTH_REDIRECT_SESSION_VAR, req.getParameter("redirect"));
    } else {
      req.getSession().removeAttribute(ADDAUTH_REDIRECT_SESSION_VAR);
    }
  }

  /**
   * Return the currently signed in user, or null if no user is signed in.
   * 
   * @param req
   *          the HttpServletRequest holding auth credentials.
   * @return the current signed in UserAccount, or null if no user signed in.
   */
  public static UserAccount getCurrentUser(HttpServletRequest req) {
    String uid = (String) req.getSession().getAttribute(UID_SESSION_VAR);
    String source = (String) req.getSession().getAttribute(SOURCE_SESSION_VAR);
    if (uid != null && source != null) { return uaProvider.getAccount(uid); }
    return null;
  }

  /**
   * Get the UserAuthSource for the currently signed in user, or null if no user is signed in.
   * 
   * @param req
   *          the HttpServletRequest holding auth credentials.
   * @return the UserAuthSource of the currently signed in UserAccount, or null if no user signed in.
   */
  public static UserAuthSource getCurrentSource(HttpServletRequest req) {
    UserAccount acct = getCurrentUser(req);
    if (acct == null) return null;
    String source = (String) req.getSession().getAttribute(SOURCE_SESSION_VAR);
    // NOTE: we could end up with null here if we race with a logout.
    if (source == null) return null;
    return uaProvider.getSource(acct, source);
  }

  /**
   * Mark a user as signed on unless the account is inactive, in which case we throw an error.
   * 
   * @param req
   *          the HttpServletRequest holding auth credentials.
   * @param user
   *          the UserAccount to sign on.
   * @param source
   *          the source from which the user account signed on.
   */
  public static void signOn(HttpServletRequest req, UserAccount user, UserAuthSource source) throws IOException {
    if (user.isDisabled()) {
      // Reject sign on attempt from disabled user
      signOff(req);
      throw new DisabledUserException();
    }
    req.getSession().setAttribute(UID_SESSION_VAR, user.getUid());
    req.getSession().setAttribute(SOURCE_SESSION_VAR, source.getSource());
    user.touch();
    source.touch();
  }

  /**
   * Mark a user as signed off.
   * 
   * @param req
   *          the HttpServletRequest holding auth credentials.
   */
  public static void signOff(HttpServletRequest req) {
    // TODO: for some sources, we want to allow actually signing the user out to clean up any credentials they may have left behind.
    // String source = (String) req.getSession().getAttribute(SOURCE_SESSION_VAR);
    req.getSession().removeAttribute(UID_SESSION_VAR);
    req.getSession().removeAttribute(SOURCE_SESSION_VAR);
  }

  public static void removeSourceIfExists(UserAccount acct, String source) {
    uaProvider.removeSourceIfExists(acct, source);
  }

  public static UserAuthSource getBySourceScreenname(String source, String screenName) {
    return uaProvider.getBySourceScreenname(source, screenName);
  }

  public static UserAuthSource createSource(UserAccount newUser, String source, String screenName, String body) {
    return uaProvider.createSource(newUser, source, screenName, body);
  }

  public static UserAccount createNewUserAccount(boolean b) {
    return uaProvider.createNewUserAccount(b);
  }
}
