<?php

	/**
	 * Issue <-> custom fields relations table
	 *
	 * @author Daniel Andre Eikeland <zegenie@zegeniestudios.net>
	 * @version 2.0
	 * @license http://www.opensource.org/licenses/mozilla1.1.php Mozilla Public License 1.1 (MPL 1.1)
	 * @package thebuggenie
	 * @subpackage tables
	 */

	/**
	 * Issue <-> custom fields relations table
	 *
	 * @package thebuggenie
	 * @subpackage tables
	 */
	class B2tIssueCustomFields extends B2DBTable
	{

		const B2DBNAME = 'bugs2_issuecustomfields';
		const ID = 'bugs2_issuecustomfields.id';
		const SCOPE = 'bugs2_issuecustomfields.scope';
		const ISSUE_ID = 'bugs2_issuecustomfields.issue_id';
		const OPTION_VALUE = 'bugs2_issuecustomfields.option_value';
		const CUSTOM_VALUE = 'bugs2_issuecustomfields.custom_value';
		const CUSTOMFIELDS_ID = 'bugs2_issuecustomfields.customfields_id';

		public function __construct()
		{
			parent::__construct(self::B2DBNAME, self::ID);
			parent::_addVarchar(self::CUSTOM_VALUE, 200);
			parent::_addForeignKeyColumn(self::ISSUE_ID, B2DB::getTable('B2tIssues'), B2tIssues::ID);
			parent::_addForeignKeyColumn(self::CUSTOMFIELDS_ID, B2DB::getTable('B2tCustomFields'), B2tCustomFields::ID);
			parent::_addForeignKeyColumn(self::OPTION_VALUE, B2DB::getTable('B2tCustomFieldOptions'), B2tCustomFieldOptions::ID);
			parent::_addForeignKeyColumn(self::SCOPE, B2DB::getTable('B2tScopes'), B2tScopes::ID);
		}

	}