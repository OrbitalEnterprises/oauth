package enterprises.orbital.oauth;

import java.util.Date;

/**
 * Interface representing a user authentication source. The embedding context should implement this interface as needed.
 */
public interface UserAuthSource {

  /**
   * Get the name of this source.
   * 
   * @return source name
   */
  public String getSource();

  /**
   * Get the displayable screen name associated with this source.
   * 
   * @return screen name
   */
  public String getScreenName();

  /**
   * Get the source-dependent body material retrieved when this source was created.
   * 
   * @return source body material
   */
  public String getBody();

  /**
   * Update the last time this source was used to login to the current time.
   */
  public void touch();

  /**
   * Change the user account this source is associated with to the given account. This is used to consolidate sources for the same logical account (e.g. if a
   * user logs in with multiple sources which should be tied together).
   * 
   * @param existing
   *          the new account to be associated with this source.
   */
  public void updateAccount(UserAccount existing);

  /**
   * Get the user account associated with this source.
   * 
   * @return the user account associated with this source.
   */
  public UserAccount getOwner();

  /**
   * Retrieve the time at which this source was last used to sign on, or null if this source has never been used.
   * 
   * @return the time at which this source was last used to sign on, or null if this source has never been used.
   */
  public Date getLastSignOn();
}
