package enterprises.orbital.oauth;

/**
 * A listener interface invoked when one of the following actions occur on a user:
 * 
 * <ul>
 * <li>a user is created for the first time on this provider.
 * <li>a user is logged into this provider.
 * <li>a user is logged out of this provider.
 * </ul>
 * 
 * One or more listeners may be registered on this provider in order to receive updates. Note that multiple events may be recieved for the same user (e.g.
 * created, followed by logged in).
 */
public interface UserActionListener {
  /**
   * A new user has been created on this provider.
   * 
   * @param newUser
   *          the newly created user.
   */
  public void userCreated(UserAccount newUser);

  /**
   * User logged in using the specified source.
   * 
   * @param user
   *          the user logged in.
   * @param source
   *          the source the user used to login.
   */
  public void loggedIn(UserAccount user, UserAuthSource source);

  /**
   * User logged out. This event only fires if a user explicitly logs out.
   * 
   * @param user
   *          the user which has just logged out.
   */
  public void loggedOut(UserAccount user);
}