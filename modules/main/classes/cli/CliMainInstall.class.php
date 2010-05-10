<?php

	/**
	 * CLI command class, main -> install
	 *
	 * @author Daniel Andre Eikeland <zegenie@zegeniestudios.net>
	 * @version 2.0
	 * @license http://www.opensource.org/licenses/mozilla1.1.php Mozilla Public License 1.1 (MPL 1.1)
	 * @package thebuggenie
	 * @subpackage core
	 */

	/**
	 * CLI command class, main -> install
	 *
	 * @package thebuggenie
	 * @subpackage core
	 */
	class CliMainInstall extends TBGCliCommand
	{

		protected function _setup()
		{
			$this->_command_name = 'install';
		}

		public function getDescription()
		{
			return "Run the installation routine";
		}

		public function do_execute()
		{
			$this->cliEcho("\nWelcome to the \"The Bug Genie\" installation wizard!\n");
			$this->cliEcho("This wizard will take you through the installation of The Bug Genie.\nRemember that you can also install The Bug Genie from your web-browser.\n");
			$this->cliEcho("Simply point your web-browser to the The Bug Genie subdirectory on your web server,\nand the installation will start.\n\n");
			$this->cliEcho("Remember that this is a pre-release version,\nwhich is not yet recommended for production use!\n\n");
			$this->cliEcho("Press ENTER to continue with the installation: ");
			try
			{
				$this->pressEnterToContinue();

				$this->cliEcho("\n");
				$this->cliEcho("How to support future development\n", 'green', 'bold');
				$this->cliEcho("Even though this software has been provided to you free of charge,\ndeveloping it would not have been possible without support from our users.\n");
				$this->cliEcho("By making a donation, or buying a support contract you can help us continue development.\n\n");
				$this->cliEcho("If this software is valuable to you - please consider supporting it.\n\n");
				$this->cliEcho("More information about supporting The Bug Genie's development can be found here:\n");
				$this->cliEcho("http://www.thebuggenie.com/giving_back.php\n\n", 'blue', 'underline');
				$this->cliEcho("Press ENTER to continue: ");

				$this->pressEnterToContinue();

				$this->cliEcho("\n");
				$this->cliEcho("License information\n", 'green', 'bold');
				$this->cliEcho("This software is Open Source Initiative approved Open Source Software.\nOpen Source Initiative Approved is a trademark of the Open Source Initiative.\n\n");
				$this->cliEcho("True to the the Open Source Definition, The Bug Genie is released\nunder the MPL 1.1 only. You can read the full license here:\n");
				$this->cliEcho("http://www.opensource.org/licenses/mozilla1.1.php\n\n", 'blue', 'underline');
				$this->cliEcho("Before you can continue the installation, you need to confirm that you \nagree to be bound by the terms in this license.\n\n");
				$this->cliEcho("Do you agree to be bound by the terms in the MPL 1.1 license?\n(type \"yes\" to agree, anything else aborts the installation): ");

				if (!$this->askToAccept()) throw new Exception($this->cliEcho('You need to accept the license to continue', 'red', 'bold'));

				$not_well = array();
				if (!is_writable('core/B2DB/'))
				{
					$not_well[] = 'b2db_perm';
				}
				if (!is_writable(TBGContext::getIncludePath()))
				{
					$not_well[] = 'root';
				}

				if (count($not_well) > 0)
				{
					$this->cliEcho("\n");
					foreach ($not_well as $afail)
					{
						switch ($afail)
						{
							case 'b2db_perm':
								$this->cliEcho("Could not write to the B2DB directory\n", 'red', 'bold');
								$this->cliEcho('The folder ');
								$this->cliEcho('include/B2DB', 'white', 'bold');
								$this->cliEcho(' folder needs to be writable');
								break;
							case 'root':
								$this->cliEcho("Could not write to the main directory\n", 'red', 'bold');
								$this->cliEcho('The top level folder must be writable during installation');
								break;
						}
					}

					throw new Exception("\n\nYou need to correct the above errors before the installation can continue.");
				}
				else
				{
					$this->cliEcho("Step 1 - database information\n");
					if (file_exists('core/B2DB/sql_parameters.inc.php'))
					{
						$this->cliEcho("You seem to already have completed this step successfully.\nDo you want to use the stored settings?\n", 'white', 'bold');
						$this->cliEcho("\nType \"no\" to enter new settings, press ENTER to use existing: ", 'white', 'bold');
						$use_existing_db_info = $this->askToDecline();
						$this->cliEcho("\n");
					}
					else
					{
						$use_existing_db_info = false;
					}
					if (!$use_existing_db_info)
					{
						$this->cliEcho("The Bug Genie uses a database to store information. To be able to connect\nto your database, The Bug Genie needs some information, such as\ndatabase type, username, password, etc.\n\n");
						$this->cliEcho("Please select what kind of database you are installing The Bug Genie on:\n");
						BaseB2DB::setHTMLException(false);
						$db_types = array();
						foreach (BaseB2DB::getDBtypes() as $db_type => $db_desc)
						{
							$db_types[] = $db_type;
							$this->cliEcho(count($db_types) . ': ' . $db_desc . "\n", 'white', 'bold');
						}
						do
						{
							$this->cliEcho('Enter the corresponding number for the database (1-' . count($db_types) . '): ');
							$db_selection = $this->getInput();
							if (!isset($db_types[((int) $db_selection - 1)])) throw new Exception($db_selection . ' is not a valid database type selection');
							$db_type = $db_types[((int) $db_selection - 1)];
							$this->cliEcho("Selected database type: ");
							$this->cliEcho($db_type . "\n\n");
							$this->cliEcho("Please enter the database hostname: \n");
							$this->cliEcho('Database hostname [localhost]: ', 'white', 'bold');
							$db_hostname = $this->getInput();
							$db_hostname = ($db_hostname == '') ? 'localhost' : $db_hostname;
							$this->cliEcho("\nPlease enter the username The Bug Genie will use to connect to the database: \n");
							$this->cliEcho('Database username: ', 'white', 'bold');
							$db_username = $this->getInput();
							$this->cliEcho("Database password (press ENTER if blank): ", 'white', 'bold');
							$db_password = $this->getInput();
							$this->cliEcho("\nPlease enter the database The Bug Genie will use.\nIf it does not exist, The Bug Genie will create it for you.\n(the default database name is ");
							$this->cliEcho("thebuggenie_db", 'white', 'bold');
							$this->cliEcho(" - press ENTER to use that):\n");
							$this->cliEcho('Database name: ', 'white', 'bold');
							$db_name = $this->getInput('thebuggenie_db');
							$this->cliEcho("\n");
							$this->cliEcho("The following settings will be used:\n");
							$this->cliEcho("Database type: \t\t", 'white', 'bold');
							$this->cliEcho($db_type . "\n");
							$this->cliEcho("Database hostname: \t", 'white', 'bold');
							$this->cliEcho($db_hostname . "\n");
							$this->cliEcho("Database username: \t", 'white', 'bold');
							$this->cliEcho($db_username . "\n");
							$this->cliEcho("Database password: \t", 'white', 'bold');
							$this->cliEcho($db_password . "\n");
							$this->cliEcho("Database name: \t\t", 'white', 'bold');
							$this->cliEcho($db_name . "\n");

							$this->cliEcho("\nIf these settings are ok, press ENTER, or anything else to retry: ");

							$e_ok = $this->askToDecline();
						}
						while (!$e_ok);
						try
						{
							BaseB2DB::setHost($db_hostname);
							BaseB2DB::setUname($db_username);
							BaseB2DB::setPasswd($db_password);
							BaseB2DB::setDBtype($db_type);
							BaseB2DB::initialize(true);
							B2DB::doConnect();
							B2DB::createDatabase($db_name);
						}
						catch (Exception $e)
						{
							throw new Exception("Could not connect to the database:\n" . $e->getMessage());
						}
						B2DB::setDBname($db_name);
						B2DB::doSelectDB();
						$this->cliEcho("\nSuccessfully connected to the database.\n", 'green');
						$this->cliEcho("Press ENTER to continue ... ");
						$this->pressEnterToContinue();
						$this->cliEcho("\n");
						$this->cliEcho("Saving database connection information ... ", 'white', 'bold');
						$this->cliEcho("\n");
						B2DB::saveConnectionParameters();
						$this->cliEcho("Successfully saved database connection information.\n", 'green');
						$this->cliEcho("\n");
					}
					else
					{
						B2DB::initialize();
						$this->cliEcho("Successfully connected to the database.\n", 'green');
						$this->cliEcho("Press ENTER to continue ... ");
						$this->pressEnterToContinue();
					}
					$this->cliEcho("\nThe Bug Genie needs some server settings to function properly...\n\n");

					do
					{
						$this->cliEcho("URL rewriting\n", 'cyan', 'bold');
						$this->cliEcho("The Bug Genie uses a technique called \"url rewriting\" - which allows for pretty\nURLs such as ") . $this->cliEcho('/issue/1', 'white', 'bold') . $this->cliEcho(' instead of ') . $this->cliEcho("viewissue.php?issue_id=1\n", 'white', 'bold');
						$this->cliEcho("Make sure you have read the URL_REWRITE document located in the root\nfolder, or at http://www.thebuggenie.com before you continue\n");
						$this->cliEcho("Press ENTER to continue ... ");
						$this->pressEnterToContinue();
						$this->cliEcho("\n");
						$this->cliEcho("Web server root URL\n", 'white', 'bold');
						$this->cliEcho("This is the root of the Web server where The Bug Genie will be running\nex: http://bugs.mycompany.com\n");
						$this->cliEcho('Enter the web URL ');
						$this->cliEcho('without', 'white', 'bold');
						$this->cliEcho(" any ending slashes\n\n");
						$this->cliEcho('Web server root URL: ', 'white', 'bold');
						$url_host = $this->getInput();
						$this->cliEcho("\n");

						$this->cliEcho("The Bug Genie subdir\n", 'white', 'bold');
						$this->cliEcho("This is the sub-path of the Web server where The Bug Genie will be located.\n");
						$this->cliEcho('Start and end this with a forward slash', 'white', 'bold');
						$this->cliEcho(". (ex: \"/thebuggenie/\")\nIf The Bug Genie is running at root, just type \"/\" (without the quotes)\n\n");
						$this->cliEcho('The Bug Genie subdir: ', 'white', 'bold');
						$url_subdir = $this->getInput();
						$this->cliEcho("\n");

						$this->cliEcho("The Bug Genie will now be accessible at\n");
						$this->cliEcho($url_host . $url_subdir, 'white', 'bold');
						$this->cliEcho("\nPress ENTER if ok, or \"no\" to try again: ");
						$e_ok = $this->askToDecline();
						$this->cliEcho("\n");
					}
					while (!$e_ok);

					$this->cliEcho("Setup can autoconfigure your .htaccess file (located in the thebuggenie/ subfolder), so you don't have to.\n");
					$this->cliEcho('Would you like setup to auto-generate the .htaccess file for you?');
					$this->cliEcho("\nPress ENTER if ok, or \"no\" to not set up the .htaccess file: ");
					$htaccess_ok = $this->askToDecline();
					$this->cliEcho("\n");

					if ($htaccess_ok)
					{
						if (!is_writable(TBGContext::getIncludePath() . 'thebuggenie/') || (file_exists(TBGContext::getIncludePath() . 'thebuggenie/.htaccess') && !is_writable(TBGContext::getIncludePath() . 'thebuggenie/.htaccess')))
						{
							$this->cliEcho("Permission denied when trying to save the [main folder]/thebuggenie/.htaccess\n", 'red', 'bold');
							$this->cliEcho("You will have to set up the .htaccess file yourself. See the README file for more information.\n", 'white', 'bold');
							$this->cliEcho('Please note: ', 'white', 'bold');
							$this->cliEcho("The Bug Genie will not function properly until the .htaccess file is properly set up!\n");
						}
						else
						{
							$content = str_replace('###PUT URL SUBDIRECTORY HERE###', $url_subdir, file_get_contents(TBGContext::getIncludePath() . 'thebuggenie/htaccess.template'));
							file_put_contents(TBGContext::getIncludePath() . 'thebuggenie/.htaccess', $content);
							if (file_get_contents(TBGContext::getIncludePath() . 'thebuggenie/.htaccess') != $content)
							{
								$this->cliEcho("Permission denied when trying to save the [main folder]/thebuggenie/.htaccess\n", 'red', 'bold');
								$this->cliEcho("You will have to set up the .htaccess file yourself. See the README file for more information.\n", 'white', 'bold');
								$this->cliEcho('Please note: ', 'white', 'bold');
								$this->cliEcho("The Bug Genie will not function properly until the .htaccess file is properly set up!\n");
							}
							else
							{
								$this->cliEcho("The .htaccess file was successfully set up...\n", 'green', 'bold');
							}
						}

					}
					else
					{
						$this->cliEcho("Skipping .htaccess auto-setup.");
					}
					$this->cliEcho("Press ENTER to continue ... ");
					$this->pressEnterToContinue();
					$this->cliEcho("\n");

					$enable_modules = array();
					
					$this->cliEcho("You will now get a list of available modules.\nTo enable the module after installation, just press ENTER.\nIf you don't want to enable the module, type \"no\".\nRemember that all these modules can be disabled/uninstalled after installation.\n\n");
					
					$this->cliEcho("Enable incoming and outgoing email? ", 'white', 'bold') . $this->cliEcho('(yes): ');
					$enable_modules['mailing'] = $this->askToDecline();
					$this->cliEcho("Enable internal messaging between users? ", 'white', 'bold') . $this->cliEcho('(yes): ');
					$enable_modules['messages'] = $this->askToDecline();
					$this->cliEcho("Enable calendar? ", 'white', 'bold') . $this->cliEcho('(yes): ');
					$enable_modules['calendar'] = $this->askToDecline();
					$this->cliEcho("Enable SCM integration? ", 'white', 'bold') . $this->cliEcho('(yes): ');
					$enable_modules['svn_integration'] = $this->askToDecline();

					$enable_modules['publish'] = true;

					$this->cliEcho("\n");
					$this->cliEcho("Creating tables ...\n", 'white', 'bold');
					$tables_path = THEBUGGENIE_PATH . 'core/classes/B2DB/';
					TBGContext::addClasspath($tables_path);
					$tables_path_handle = opendir($tables_path);
					$tables_created = array();
					while ($table_class_file = readdir($tables_path_handle))
					{
						if (($tablename = substr($table_class_file, 0, strpos($table_class_file, '.'))) != '')
						{
							B2DB::getTable($tablename)->create();
							$this->cliEcho("Creating table {$tablename}\n", 'white', 'bold');
						}
					}

					$this->cliEcho("\n");
					$this->cliEcho("All tables successfully created...\n\n", 'green', 'bold');
					$this->cliEcho("Setting up initial scope... \n", 'white', 'bold');
					TBGContext::reinitializeI18n('en_US');
					$scope = TBGScope::createNew('The default scope', '');
					TBGSettings::saveSetting('language', 'en_US', 'core', 1);
					$scope->setHostname($url_host);
					$scope->save();
					TBGContext::setScope($scope);
					TBGSettings::saveSetting('url_subdir', $url_subdir, 'core', 1);
					$this->cliEcho("Initial scope setup successfully... \n\n", 'green', 'bold');

					$this->cliEcho("Setting up modules... \n", 'white', 'bold');
					try
					{
						foreach ($enable_modules as $module => $install)
						{
							if ((bool) $install && file_exists(TBGContext::getIncludePath() . "modules/{$module}/module"))
							{
								$this->cliEcho("Installing {$module}... \n", 'white', 'bold');
								TBGContext::addClasspath(TBGContext::getIncludePath() . "modules/{$module}/classes/");
								if (file_exists(TBGContext::getIncludePath() . "modules/{$module}/classes/B2DB/"))
								{
									TBGContext::addClasspath(TBGContext::getIncludePath() . "modules/{$module}/classes/B2DB/");
								}
								$classname = file_get_contents(TBGContext::getIncludePath() . "modules/{$module}/class");
								call_user_func(array($classname, 'install'), 1);
								$this->cliEcho("Module {$module} installed successfully...\n", 'green', 'bold');
							}
						}

						$this->cliEcho("\n");
						$this->cliEcho("All modules installed successfully...\n", 'green', 'bold');
						$this->cliEcho("Please press ENTER to finish installation... ");
						$this->pressEnterToContinue();

						if (!is_writable(TBGContext::getIncludePath() . 'installed'))
						{
							$this->cliEcho("\n");
							$this->cliEcho("Could not create the 'installed' file.\n", 'red', 'bold');
							$this->cliEcho("Please create the file ");
							$this->cliEcho(TBGContext::getIncludePath() . "installed\n", 'white', 'bold');
							$this->cliEcho("with the following line inside:\n");
							$this->cliEcho('3.0, installed ' . date('d.m.Y H:i'), 'blue', 'bold');
							$this->cliEcho("\n\n");
							$this->cliEcho("When that is done, please press ENTER to continue ... ");
							$this->pressEnterToContinue();
						}
						else
						{
							file_put_contents(TBGContext::getIncludePath() . 'installed', '3.0, installed ' . date('d.m.Y H:i'));
						}

						$this->cliEcho("\nThe installation was completed successfully!\n", 'green', 'bold');
						$this->cliEcho("\nTo use The Bug Genie, access " . $url_host . $url_subdir . "index.php with a web-browser.\n");
						$this->cliEcho("The default username is ") . $this->cliEcho('Administrator') . $this->cliEcho(' and the password is ') . $this->cliEcho('admin');
						$this->cliEcho("\n\nThank you for trying this The Bug Genie test release!\n");
						$this->cliEcho("\nFor support, please visit ") . $this->cliEcho('http://www.thebuggenie.com/', 'blue', 'underline');
						$this->cliEcho("\n");
					}
					catch (Exception $e)
					{
						throw new Exception("Could not install the $module module:\n" . $e->getMessage());
					}

				}
			}
			catch (Exception $e)
			{
				$this->cliEcho("\n\nThe installation was interrupted\n", 'red');
				$this->cliEcho($e->getMessage() . "\n");
			}
			$this->cliEcho("\n");
		}

	}