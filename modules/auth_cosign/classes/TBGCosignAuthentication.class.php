<?php

	/**
	 * Cosign Authentication
	 *
	 * @author Samuel Leathers
	 * @version 0.1
	 * @license http://www.opensource.org/licenses/mozilla1.1.php Mozilla Public License 1.1 (MPL 1.1)
	 * @package auth_cosign
	 * @subpackage core
	 */

	/**
	 * Cosign Authentication
	 *
	 * @package auth_cosign
	 * @subpackage core
	 */
	class TBGCosignAuthentication extends TBGModule
	{

		protected $_longname = 'Cosign Authentication';
		
		protected $_description = 'Allows authentication against via cosign webaccess realm';
		
		protected $_module_config_title = 'Cosign Authentication';
		
		protected $_module_config_description = 'Configure server connection settings';
		
		protected $_module_version = '0.1';
		
		protected $_has_config_settings = true;

		/**
		 * Return an instance of this module
		 *
		 * @return Cosign Authentication
		 */
		public static function getModule()
		{
			return TBGContext::getModule('auth_cosign');
		}

        public static function upgrade() {

        }
		protected function _initialize()
		{
		}
		
		protected function _addRoutes()
		{
		}

		protected function _install($scope)
		{
		}

		protected function _uninstall()
		{
		}
		
		public final function getType()
		{
			return parent::MODULE_AUTH;
		}

		public function getRoute()
		{
			return TBGContext::getRouting()->generate('cosign_authentication_index');
		}

		public function postConfigSettings(TBGRequest $request)
		{
			$settings = array('hostname', 'u_type', 'g_type', 'b_dn', 'groups', 'dn_attr', 'u_attr', 'g_attr', 'e_attr', 'f_attr', 'g_dn', 'control_user', 'control_pass');
			foreach ($settings as $setting)
			{
				if (($setting == 'u_type' || $setting == 'g_type' || $setting == 'dn_attr') && $request->getParameter($setting) == '')
				{
					if ($setting == 'u_type')
					{
						$this->saveSetting($setting, 'person');
					}
					elseif ($setting == 'g_type')
					{
						$this->saveSetting($setting, 'group');
					}
					else
					{
						$this->saveSetting($setting, 'entrydn');
					}
				}
				else
				{
					if ($request->hasParameter($setting))
					{
						$this->saveSetting($setting, $request->getParameter($setting));
					}
				}
			}
		}
		
		public function doLogin($username, $password, $mode = 1)
		{	
			try
			{
				/*
				 * If we are performing a login, now bind to the user and see if the credentials
				 * are valid. We bind using the full DN of the user, so no need for DOMAIN\ stuff
				 * on Windows, and more importantly it fixes other servers.
				 * 
				 * If the bind fails (exception), we throw a nicer exception and don't continue.
				 */
				if ($mode == 1)
				{
					try
					{
                        if(isset($_SERVER['REMOTE_USER'])) {
                            $username = $_SERVER['REMOTE_USER'];

                        }
					}
					catch (Exception $e)
					{
						throw new Exception('Your password was not accepted by the server');
					}
				}
			}
			catch (Exception $e)
			{
				throw $e;
			}
			
			try
			{
				/*
				 * Get the user object. If the user exists, update the user's
				 * data from the directory.
				 */
				$user = TBGUser::getByUsername($username);
				if ($user instanceof TBGUser)
				{					
					$user->setBuddyname($realname);
					$user->setRealname($realname);
					$user->setPassword($user->getJoinedDate().$username); // update password
					$user->setEmail($email); // update email address
					$user->save();
				}
				else
				{
					/*
					 * If not, and we are performing an initial login, create the user object
					 * if we are validating a log in, kick the user out as the session is invalid.
					 */
					if ($mode == 1)
					{						
						// create user
						$user = new TBGUser();
						$user->setUsername($_SERVER['REMOTE_USER']);
						$user->setRealname('temporary');
						$user->setBuddyname($username);
						$user->setEmail('temporary');
						$user->setEnabled();
						$user->setActivated();
						$user->setJoined();
						$user->setPassword($user->getJoinedDate().$username);
						$user->save();
					}
					else
					{
						throw new Exception('User does not exist in TBG');
					}
				}
			}
			catch (Exception $e)
			{
				throw $e;
			}

			
			/*
			 * Set cookies and return user row for general operations.
			 */
			TBGContext::getResponse()->setCookie('tbg3_username', $username);
			TBGContext::getResponse()->setCookie('tbg3_password', TBGUser::hashPassword($user->getJoinedDate().$username));

			return TBGUsersTable::getTable()->getByUsername($username);
		}

		public function verifyLogin($username)
		{
			return $this->doLogin($username, 'a', 2);
		}
        public function isOutdated() {
            return false;
        }
	}

