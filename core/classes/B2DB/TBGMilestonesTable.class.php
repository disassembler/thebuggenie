<?php

	/**
	 * Milestones table
	 *
	 * @author Daniel Andre Eikeland <zegenie@zegeniestudios.net>
	 * @version 2.0
	 * @license http://www.opensource.org/licenses/mozilla1.1.php Mozilla Public License 1.1 (MPL 1.1)
	 * @package thebuggenie
	 * @subpackage tables
	 */

	/**
	 * Milestones table
	 *
	 * @package thebuggenie
	 * @subpackage tables
	 */
	class TBGMilestonesTable extends B2DBTable 
	{

		const B2DBNAME = 'milestones';
		const ID = 'milestones.id';
		const SCOPE = 'milestones.scope';
		const NAME = 'milestones.name';
		const PROJECT = 'milestones.project';
		const VISIBLE = 'milestones.visible';
		const DESCRIPTION = 'milestones.description';
		const MILESTONE_TYPE = 'milestones.milestone_type';
		const REACHED = 'milestones.reached';
		const STARTING = 'milestones.starting';
		const SCHEDULED = 'milestones.scheduled';
		
		public function __construct()
		{
			parent::__construct(self::B2DBNAME, self::ID);
			parent::_addVarchar(self::NAME, 100);
			parent::_addBoolean(self::VISIBLE, true);
			parent::_addText(self::DESCRIPTION, false);
			parent::_addInteger(self::REACHED, 10);
			parent::_addInteger(self::MILESTONE_TYPE, 2);
			parent::_addInteger(self::STARTING, 10);
			parent::_addInteger(self::SCHEDULED, 10);
			parent::_addForeignKeyColumn(self::PROJECT, B2DB::getTable('TBGProjectsTable'), TBGProjectsTable::ID);
			parent::_addForeignKeyColumn(self::SCOPE, B2DB::getTable('TBGScopesTable'), TBGScopesTable::ID);
		}
		
		public function createNew($name, $type, $project_id)
		{
			$crit = $this->getCriteria();
			$crit->addInsert(self::NAME, $name);
			$crit->addInsert(self::MILESTONE_TYPE, $type);
			$crit->addInsert(self::PROJECT, $project_id);
			$crit->addInsert(self::SCOPE, TBGContext::getScope()->getID());
			$res = $this->doInsert($crit);
			
			return $res->getInsertID();
		}
		
		public function getAllByProjectID($project_id)
		{
			$crit = $this->getCriteria();
			$crit->addWhere(self::PROJECT, $project_id);
			$crit->addOrderBy(self::SCHEDULED, B2DBCriteria::SORT_ASC);
			$res = $this->doSelect($crit);
			return $res;
		}

		public function getMilestonesByProjectID($project_id)
		{
			$crit = $this->getCriteria();
			$crit->addWhere(self::PROJECT, $project_id);
			$crit->addWhere(self::MILESTONE_TYPE, TBGMilestone::TYPE_REGULAR);
			$crit->addOrderBy(self::SCHEDULED, B2DBCriteria::SORT_ASC);
			$res = $this->doSelect($crit);
			return $res;
		}

		public function getSprintsByProjectID($project_id)
		{
			$crit = $this->getCriteria();
			$crit->addWhere(self::PROJECT, $project_id);
			$crit->addWhere(self::MILESTONE_TYPE, TBGMilestone::TYPE_SCRUMSPRINT);
			$crit->addOrderBy(self::SCHEDULED, B2DBCriteria::SORT_ASC);
			$res = $this->doSelect($crit);
			return $res;
		}

		public function setReached($milestone_id)
		{
			$crit = $this->getCriteria();
			$crit->addUpdate(self::REACHED, $_SERVER["REQUEST_TIME"]);
			$this->doUpdateById($crit, $milestone_id);
		}
		
	}