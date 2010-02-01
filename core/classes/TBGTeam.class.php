<?php

	/**
	 * Team class
	 *
	 * @author Daniel Andre Eikeland <zegenie@zegeniestudios.net>
	 * @version 2.0
	 * @license http://www.opensource.org/licenses/mozilla1.1.php Mozilla Public License 1.1 (MPL 1.1)
	 * @package thebuggenie
	 * @subpackage main
	 */

	/**
	 * Team class
	 *
	 * @package thebuggenie
	 * @subpackage main
	 */
	class TBGTeam extends TBGIdentifiableClass implements TBGIdentifiable 
	{
		
		protected $_members = null;
		
		protected static $_teams = null;
		
		public static function getAll()
		{
			if (self::$_teams === null)
			{
				self::$_teams = array();
				if ($res = B2DB::getTable('B2tTeams')->getAll())
				{
					while ($row = $res->getNextRow())
					{
						self::$_teams[$row->get(B2tTeams::ID)] = TBGFactory::teamLab($row->get(B2tTeams::ID), $row);
					}
				}
			}
			return self::$_teams;
		}
		
		/**
		 * Class constructor
		 *
		 * @param integer $t_id
		 */
		public function __construct($t_id, $row = null)
		{
			$this->_itemid = $t_id;
			if ($row == null)
			{
				$crit = new B2DBCriteria();
				$crit->addWhere(B2tTeams::SCOPE, TBGContext::getScope()->getID());
				$row = B2DB::getTable('B2tTeams')->doSelectById($t_id, $crit);
			}
			
			if ($row instanceof B2DBRow)
			{
				$this->_name = $row->get(B2tTeams::TEAMNAME);
			}
			else
			{
				throw new Exception('This team does not exist');
			}
		}
		
		public function __toString()
		{
			return "" . $this->_name;
		}
		
		public function getName()
		{
			return $this->_name;
		}
		
		public function getID()
		{
			return $this->_itemid;
		}

		public function getType()
		{
			return self::TYPE_TEAM;
		}
		
		/**
		 * Creates a team
		 *
		 * @param unknown_type $groupname
		 * @return TBGTeam
		 */
		public static function createNew($teamname)
		{
			$crit = new B2DBCriteria();
			$crit->addInsert(B2tTeams::TEAMNAME, $teamname);
			$crit->addInsert(B2tTeams::SCOPE, TBGContext::getScope()->getID());
			$res = B2DB::getTable('B2tTeams')->doInsert($crit);
			return TBGFactory::teamLab($res->getInsertID());
		}
		
		/**
		 * Adds a user to the team
		 *
		 * @param integer $uid
		 */
		public function addMember($uid)
		{
			$crit = new B2DBCriteria();
			$crit->addInsert(B2tTeamMembers::SCOPE, TBGContext::getScope()->getID());
			$crit->addInsert(B2tTeamMembers::TID, $this->_itemid);
			$crit->addInsert(B2tTeamMembers::UID, $uid);
			B2DB::getTable('B2tTeamMembers')->doInsert($crit);
			if ($this->_members === null)
			{
				$this->_members = array();
			}
			$this->_members[] = $uid;
			array_unique($this->_members);
		}
		
		public function setName($tname)
		{
			$crit = new B2DBCriteria();
			$crit->addUpdate(B2tTeams::TEAMNAME, $tname);
			B2DB::getTable('B2tTeams')->doUpdateById($crit, $this->getID());
			$this->_name = $tname;
		}
		
		public function getMembersIDs()
		{
			if ($this->_members === null)
			{
				$this->_members = array();
				$crit = new B2DBCriteria();
				$crit->addWhere(B2tTeamMembers::TID, $this->_itemid);
				$res = B2DB::getTable('B2tTeamMembers')->doSelect($crit);
				while ($row = $res->getNextRow())
				{
					$this->_members[] = $row->get(B2tTeamMembers::UID);
				}
			}
			return $this->_members;
		}

		/**
		 * Removes a user from the team
		 *
		 * @param integer $uid
		 */
		public function removeMember($uid)
		{
			$crit = new B2DBCriteria();
			$crit->addWhere(B2tTeamMembers::UID, $uid);
			$crit->addWhere(B2tTeamMembers::TID, $this->_itemid);
			B2DB::getTable('B2tTeamMembers')->doDelete($crit);
		}
		
		public function delete()
		{
			$res = B2DB::getTable('B2tTeams')->doDeleteById($this->getID());
			$crit = new B2DBCriteria();
			$crit->addWhere(B2tTeamMembers::TID, $this->getID());
			$res = B2DB::getTable('B2tTeamMembers')->doDelete($crit);
		}
		
		public static function findTeams($details)
		{
			$crit = new B2DBCriteria();
			$crit->addWhere(B2tTeams::TEAMNAME, "%$details%", B2DBCriteria::DB_LIKE);
			$teams = array();
			if ($res = B2DB::getTable('B2tTeams')->doSelect($crit))
			{
				while ($row = $res->getNextRow())
				{
					$teams[$row->get(B2tTeams::ID)] = TBGFactory::teamLab($row->get(B2tTeams::ID), $row);
				}
			}
			return $teams;
		}
		
		
	}