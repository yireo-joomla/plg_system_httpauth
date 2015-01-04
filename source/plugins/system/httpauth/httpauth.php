<?php
/**
 * Joomla! System plugin - HTTP Authentication
 *
 * @author Yireo (info@yireo.com)
 * @copyright Copyright 2015 Yireo.com. All rights reserved
 * @license GNU Public License
 * @link http://www.yireo.com
 */

// no direct access
defined( '_JEXEC' ) or die( 'Restricted access' );

// Import parent library
jimport( 'joomla.plugin.plugin');

/**
* HTTP Authentication System Plugin
*
*/
class plgSystemHttpAuth extends JPlugin
{
    /*
     * Catch the event onAfterInitialise
     * 
     * @access public
     * @param null
     * @return null
     */
	public function onAfterInitialise()
	{
        // Load system variables
		$app = JFactory::getApplication();
        $user = JFactory::getUser();

        // Some stuff for Joomla! 3.2 and later
		$app->rememberCookieLifetime = time() + (24 * 60 * 60);
		$app->rememberCookieSecure   = 1;
		$app->rememberCookieLength   = 16;

        // Only allow usage from within the frontend
		if($app->getName() != 'site') {
			return;
		}

        // If the current user is not a guest, authentication has already occurred
        if($user->guest == 0) {
            return;
        }

        // Allow a page to redirect the user to
        $redirect = $this->params->get('redirect');
        if($redirect > 0) {
            $redirect = JRoute::_('index.php?Itemid='.$redirect);
        } else {
            $redirect = JURI::current();
        }

        // Construct the options for authentication
		$options = array();
		$options['remember'] = true;
		$options['return'] = $redirect;

        // Construct the credentials based on HTTP Authentication
		$credentials = array();
        $credentials['username'] = (isset($_SERVER['PHP_AUTH_USER'])) ? $_SERVER['PHP_AUTH_USER'] : null;
        $credentials['password'] = (isset($_SERVER['PHP_AUTH_PW'])) ? $_SERVER['PHP_AUTH_PW'] : null;
        $credentials['secretkey'] = '';

        // If the credentials are empty, there's no point into using them
        if(empty($credentials['username']) || empty($credentials['password'])) {
            $this->showHttpAuth();
            return;
        }

        // Try to login
		$rt = $app->login($credentials, $options);

        // Detect authentication failures
		if($rt != true || JError::isError($rt)) {
            $this->showHttpAuth();
            return;
        }

        // Act on authentication success
		$app->setUserState('rememberLogin', false);
		$app->setUserState('users.login.form.data', array());

        // Redirect if needed
        if(!empty($redirect)) {
            $app->redirect($redirect);
            return;
        }
    }

    /*
     * Helper method to display the HTTP Authentication 
     * 
     * @access public
     * @param null
     * @return null
     */
    public function showHttpAuth()
    {
        // Include IP-addresses
        $include_ip = trim($this->params->get('include_ip'));
        if(!empty($include_ip)) {
            $include_ips = explode(',', $include_ip);
            $match = false;
            foreach($include_ips as $include_ip) {
                if($_SERVER['REMOTE_ADDR'] == trim($include_ip)) {
                    $match = true;
                    break;
                }
            }

            // There is no match, so skip authentication
            if($match == false) {
                return false;
            }
        }

        // Exclude IP-addresses
        $exclude_ip = trim($this->params->get('exclude_ip'));
        if(!empty($exclude_ip)) {
            $exclude_ips = explode(',', $exclude_ip);
            foreach($exclude_ips as $exclude_ip) {
                if($_SERVER['REMOTE_ADDR'] == trim($exclude_ip)) {
                    return false;
                }
            }
        }

        // Display HTTP Authentication
        header('WWW-Authenticate: Basic realm="My Realm"');
        header('HTTP/1.0 401 Unauthorized');
        echo JText::_('Unable to authenticate');

        // Close the application
        JFactory::getApplication()->close();
    }
}
