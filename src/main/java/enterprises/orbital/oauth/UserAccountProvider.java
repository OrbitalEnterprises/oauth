package enterprises.orbital.oauth;

/**
 * Interface which should be implemented by the embedding context to provide user account information when needed.
 */
public interface UserAccountProvider {

  /**
   * Retrieve the account with the specified ID, or null if no such account exists.
   * 
   * @param uid
   *          the account ID to retrieve.
   * @return the specified account, or null if no such account exists.
   */
  public UserAccount getAccount(String uid);

  /**
   * Retrieve the named source for the given UserAccount, or null if no such account exists.
   * 
   * @param acct
   *          the account for which a source will be retrieved.
   * @param source
   *          the source to retrieve.
   * @return the specified UserAuthSource, or null if no such source exists.
   */
  public UserAuthSource getSource(UserAccount acct, String source);

  /**
   * Remove a named source from a UserAccount. Fails silently if the named source does not exist.
   * 
   * @param acct
   *          the account from which the source will be removed.
   * @param source
   *          the name of the source to remove.
   */
  public void removeSourceIfExists(UserAccount acct, String source);

  /**
   * Get the source with the given source name and screen name, or null if no such source exists.
   * 
   * @param source
   *          the source to retrieve.
   * @param screenName
   *          the screen name associated with the source to retrieve.
   * @return the specified source, or null if no such source exists.
   */
  public UserAuthSource getBySourceScreenname(String source, String screenName);

  /**
   * Create and associate a new source with the given user. If a source with the given name already exists, then it will be replaced by the new source.
   * 
   * @param newUser
   *          the user to which the new source will be associated.
   * @param source
   *          the name of the source.
   * @param screenName
   *          the screen name associated with this source.
   * @param body
   *          the "body" or other account context which should be associated with this source.
   * @return the new source.
   */
  public UserAuthSource createSource(UserAccount newUser, String source, String screenName, String body);

  /**
   * Create and store a new user account.
   * 
   * @param disabled
   *          if true, mark the account as disabled (unable to login).
   * @return the new user account.
   */
  public UserAccount createNewUserAccount(boolean disabled);

}
