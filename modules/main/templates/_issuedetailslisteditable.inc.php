<div id="viewissue_left_box_issuetype">
	<div id="issuetype_header" class="hoverable <?php if ($issue->isIssuetypeChanged()): ?>issue_detail_changed<?php endif; ?><?php if (!$issue->isIssuetypeMerged()): ?> issue_detail_unmerged<?php endif; ?>">
		<?php if ($issue->isEditable() && $issue->canEditIssuetype()): ?>
			<a href="javascript:void(0);" onclick="revertField('<?php echo make_url('issue_revertfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => 'issuetype')); ?>', 'issuetype');" title="<?php echo __('Undo this change'); ?>"><?php echo image_tag('undo.png', array('class' => 'undo')); ?></a>
			<?php echo image_tag('spinning_20.gif', array('style' => 'display: none; float: left; margin: 5px 5px 0 0;', 'id' => 'issuetype_undo_spinning')); ?>
			<a href="javascript:void(0);" onclick="$('issuetype_change').toggle();" title="<?php echo __('Click to change issue type'); ?>"><?php echo image_tag('action_dropdown_small.png', array('class' => 'dropdown')); ?></a>
		<?php endif; ?>
		<table cellpadding=0 cellspacing=0 id="issuetype_table"<?php if (!$issue->getIssueType() instanceof TBGDatatype): ?> style="display: none;"<?php endif; ?>>
			<tr>
				<td style="width: 24px; padding: 2px 0 0 0;"><?php echo image_tag($issue->getIssueType()->getIcon() . '_small.png', array('id' => 'issuetype_image')); ?></td>
				<td style="padding: 0 0 0 5px;" id="issuetype_content"><?php echo $issue->getIssueType()->getName(); ?></td>
			</tr>
		</table>
		<div class="faded_out" id="no_issuetype"<?php if ($issue->getIssueType() instanceof TBGDatatype): ?> style="display: none;"<?php endif; ?>><?php echo __('Unknown issue type'); ?></div>
	</div>
</div>
<?php if ($issue->isEditable() && $issue->canEditIssuetype()): ?>
	<div id="issuetype_change" class="rounded_box white shadowed" style="display: none; width: 280px; position: absolute; z-index: 10001; margin: 5px 0 5px 0;">
		<div class="dropdown_header"><?php echo __('Set issue type'); ?></div>
		<div class="dropdown_content">
			<?php echo __('Select a new issue type'); ?>:<br>
			<table cellpadding="0" cellspacing="0">
				<?php foreach ($issuetypes as $issuetype): ?>
					<tr>
						<td style="width: 16px;"><?php echo image_tag($issuetype->getIcon() . '_tiny.png'); ?></td>
						<td style="padding-left: 5px;"><a href="javascript:void(0);" onclick="setField('<?php echo make_url('issue_setfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => 'issuetype', 'issuetype_id' => $issuetype->getID())); ?>', 'issuetype');"><?php echo $issuetype->getName(); ?></a></td>
					</tr>
				<?php endforeach; ?>
			</table>
			<div id="issuetype_spinning" style="margin-top: 3px; display: none;"><?php echo image_tag('spinning_20.gif', array('style' => 'float: left; margin-right: 5px;')) . '&nbsp;' . __('Please wait'); ?>...</div>
		</div>
		<div id="issuetype_change_error" class="error_message" style="display: none;"></div>
	</div>
<?php endif; ?>
<div id="viewissue_left_box_status">
	<div id="status_header" class="hoverable <?php if ($issue->isStatusChanged()): ?>issue_detail_changed<?php endif; ?><?php if (!$issue->isStatusMerged()): ?> issue_detail_unmerged<?php endif; ?>">
		<?php if ($issue->isUpdateable() && $issue->canEditStatus()): ?>
			<a href="javascript:void(0);" onclick="revertField('<?php echo make_url('issue_revertfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => 'status')); ?>', 'status');" title="<?php echo __('Undo this change'); ?>"><?php echo image_tag('undo.png', array('class' => 'undo')); ?></a>
			<?php echo image_tag('spinning_16.gif', array('style' => 'display: none; float: left; margin-right: 5px;', 'id' => 'status_undo_spinning')); ?>
			<a href="javascript:void(0);" onclick="$('status_change').toggle();" title="<?php echo __('Click to change status'); ?>"><?php echo image_tag('action_dropdown_small.png', array('class' => 'dropdown')); ?></a>
		<?php endif; ?>
		<table style="table-layout: auto; width: 240px;<?php if (!$issue->getStatus() instanceof TBGDatatype): ?> display: none;<?php endif; ?>" cellpadding=0 cellspacing=0 id="status_table">
			<tr>
				<td style="width: 24px;"><div style="border: 1px solid #AAA; background-color: <?php echo ($issue->getStatus() instanceof TBGDatatype) ? $issue->getStatus()->getColor() : '#FFF'; ?>; font-size: 1px; width: 20px; height: 15px; margin-right: 2px;" id="status_color">&nbsp;</div></td>
				<td style="padding-left: 5px;" id="status_content" class="<?php if ($issue->isStatusChanged()): ?>issue_detail_changed<?php endif; ?><?php if (!$issue->isStatusMerged()): ?> issue_detail_unmerged<?php endif; ?>"><?php if ($issue->getStatus() instanceof TBGDatatype) echo $issue->getStatus()->getName(); ?></td>
			</tr>
		</table>
		<span class="faded_out" id="no_status"<?php if ($issue->getStatus() instanceof TBGDatatype): ?> style="display: none;"<?php endif; ?>><?php echo __('Status not determined'); ?></span>
	</div>
</div>
<?php if ($issue->isUpdateable() && $issue->canEditStatus()): ?>
	<div class="rounded_box white shadowed" id="status_change" style="display: none; width: 280px; position: absolute; z-index: 10001; margin: 5px 0 5px 0; padding: 5px;">
		<div class="dropdown_header"><?php echo __('Set status'); ?></div>
		<div class="dropdown_content">
			<a href="javascript:void(0);" onclick="setField('<?php echo make_url('issue_setfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => 'status', 'status_id' => 0)); ?>', 'status');"><?php echo __('Clear the status'); ?></a><br>
		</div>
		<div class="dropdown_content">
			<?php echo __('%clear_the_status% or click to select a new status', array('%clear_the_status%' => '')); ?>:<br>
			<table cellpadding="0" cellspacing="0">
				<?php foreach ($statuses as $status): ?>
					<?php if (!$status->canUserSet($tbg_user)) continue; ?>
					<tr>
						<td style="width: 16px;"><div style="border: 1px solid #AAA; background-color: <?php echo $status->getColor(); ?>; font-size: 1px; width: 16px; height: 15px; margin-right: 2px;">&nbsp;</div></td>
						<td style="padding-left: 5px;"><a href="javascript:void(0);" onclick="setField('<?php echo make_url('issue_setfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => 'status', 'status_id' => $status->getID())); ?>', 'status');"><?php echo $status->getName(); ?></a></td>
					</tr>
				<?php endforeach; ?>
			</table>
			<div id="status_spinning" style="margin-top: 3px; display: none;"><?php echo image_tag('spinning_20.gif', array('style' => 'float: left; margin-right: 5px;')) . '&nbsp;' . __('Please wait'); ?>...</div>
		</div>
		<div id="status_change_error" class="error_message" style="display: none;"></div>
	</div>
<?php endif; ?>
<dl class="viewissue_list" id="assigned_to_field">
	<dt id="assigned_to_header" class="<?php if ($issue->isAssignedToChanged()): ?>issue_detail_changed<?php endif; ?><?php if (!$issue->isAssignedToMerged()): ?> issue_detail_unmerged<?php endif; ?>"><?php echo __('Assigned to'); ?></dt>
	<dd id="assigned_to_content" class="<?php if ($issue->isAssignedToChanged()): ?>issue_detail_changed<?php endif; ?><?php if (!$issue->isAssignedToMerged()): ?> issue_detail_unmerged<?php endif; ?>">
		<?php if ($issue->canEditAssignedTo()): ?>
			<a href="javascript:void(0);" onclick="revertField('<?php echo make_url('issue_revertfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => 'assigned_to')); ?>', 'assigned_to');" title="<?php echo __('Undo this change'); ?>"><?php echo image_tag('undo.png', array('class' => 'undo')); ?></a>
			<?php echo image_tag('spinning_16.gif', array('style' => 'display: none; float: left; margin-right: 5px;', 'id' => 'assigned_to_undo_spinning')); ?>
			<a href="javascript:void(0);" onclick="$('assigned_to_change').toggle();" title="<?php echo __('Click to change assignee'); ?>"><?php echo image_tag('action_dropdown_small.png', array('class' => 'dropdown')); ?></a>
		<?php endif; ?>
		<div style="width: 170px; display: <?php if ($issue->isAssigned()): ?>inline<?php else: ?>none<?php endif; ?>;" id="assigned_to_name">
			<?php if ($issue->getAssigneeType() == TBGIdentifiableClass::TYPE_USER): ?>
				<?php echo include_component('main/userdropdown', array('user' => $issue->getAssignee())); ?>
			<?php elseif ($issue->getAssigneeType() == TBGIdentifiableClass::TYPE_TEAM): ?>
				<?php echo include_component('main/teamdropdown', array('team' => $issue->getAssignee())); ?>
			<?php endif; ?>
		</div>
		<span class="faded_out" id="no_assigned_to"<?php if ($issue->isAssigned()): ?> style="display: none;"<?php endif; ?>><?php echo __('Not assigned to anyone'); ?></span>
	</dd>
</dl>
<?php if ($issue->canEditAssignedTo()): ?>
	<?php include_component('identifiableselector', array(	'html_id' 			=> 'assigned_to_change', 
															'header' 			=> __('Assign this issue'),
															'callback'		 	=> "setField('" . make_url('issue_setfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => 'assigned_to', 'identifiable_type' => '%identifiable_type%', 'value' => '%identifiable_value%')) . "', 'assigned_to');",
															'teamup_callback' 	=> "setField('" . make_url('issue_setfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => 'assigned_to', 'identifiable_type' => '%identifiable_type%', 'value' => '%identifiable_value%', 'teamup' => true)) . "', 'assigned_to');",
															'clear_link_text'	=> __('Clear current assignee'),
															'base_id'			=> 'assigned_to',
															'include_teams'		=> true,
															'absolute' => true)); ?>
<?php endif; ?>
<dl class="viewissue_list" id="percent_complete_field"<?php if (!$issue->isPercentCompletedVisible()): ?> style="display: none;"<?php endif; ?>>
	<dt id="percent_header" class="<?php if ($issue->isPercentCompletedChanged()): ?>issue_detail_changed<?php endif; ?><?php if (!$issue->isPercentCompletedMerged()): ?> issue_detail_unmerged<?php endif; ?>"><?php echo __('Progress'); ?></dt>
	<dd id="percent_content" class="<?php if ($issue->isPercentCompletedChanged()): ?>issue_detail_changed<?php endif; ?><?php if (!$issue->isPercentCompletedMerged()): ?> issue_detail_unmerged<?php endif; ?>">
		<div style="width: 210px;">
			<?php if ($issue->canEditPercentage() && $issue->isUpdateable()): ?>
				<a href="javascript:void(0);" onclick="updatePercent('<?php echo make_url('issue_revertfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => 'percent')); ?>', 'percent');" title="<?php echo __('Undo this change'); ?>"><?php echo image_tag('undo.png', array('class' => 'undo')); ?></a>
				<?php echo image_tag('spinning_16.gif', array('style' => 'display: none; float: right; margin-left: 5px;', 'id' => 'percent_spinning')); ?>
				<table style="table-layout: fixed; width: 165px;" cellpadding=0 cellspacing=0>
					<tr id="percentage_tds">
						<?php for ($cc = 0; $cc <= 100; $cc++): ?>
							<td class="<?php if ($issue->getPercentCompleted() <= $cc): ?>percent_unfilled<?php else: ?>percent_filled<?php endif; ?>" style="font-size: 1px; width: 1%; height: 14px;">
								<a href="javascript:void(0);" onclick="updatePercent('<?php echo make_url('issue_setfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => 'percent', 'percent' => $cc)); ?>', 'set');" title="<?php echo __('Set to %pct% percent', array('%pct%' => $cc)); ?>">&nbsp;</a>
							</td>
						<?php endfor; ?>
					</tr>
				</table>
			<?php else: ?>
				<?php include_template('main/percentbar', array('percent' => $issue->getPercentCompleted(), 'height' => 14)); ?>
			<?php endif; ?>
		</div>
	</dd>
</dl>
<div style="clear: both;"> </div>
<div style="margin: 0;<?php if (!$issue->isUserPainVisible()): ?> display: none;<?php endif; ?>" id="user_pain_field">
	<dl class="viewissue_list" id="pain_bug_type_field">
		<dt id="pain_bug_type_header" class="<?php if ($issue->isPainBugTypeChanged()): ?>issue_detail_changed<?php endif; ?><?php if (!$issue->isPainBugTypeMerged()): ?> issue_detail_unmerged<?php endif; ?>"><?php echo __('Type of bug'); ?></dt>
		<dd id="pain_bug_type_content" class="<?php if ($issue->isPainBugTypeChanged()): ?>issue_detail_changed<?php endif; ?><?php if (!$issue->isPainBugTypeMerged()): ?> issue_detail_unmerged<?php endif; ?>">
			<?php if ($issue->isEditable() && $issue->canEditUserPain()): ?>
				<a href="javascript:void(0);" onclick="revertField('<?php echo make_url('issue_revertfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => 'pain_bug_type')); ?>', 'pain_bug_type');" title="<?php echo __('Undo this change'); ?>"><?php echo image_tag('undo.png', array('class' => 'undo')); ?></a>
				<?php echo image_tag('spinning_16.gif', array('style' => 'display: none; float: left; margin-right: 5px;', 'id' => 'pain_bug_type_undo_spinning')); ?>
				<a href="javascript:void(0);" onclick="$('pain_bug_type_change').toggle();" title="<?php echo __('Click to triage type of bug'); ?>"><?php echo image_tag('action_dropdown_small.png', array('class' => 'dropdown')); ?></a>
			<?php endif; ?>
			<span id="pain_bug_type_name"<?php if (!$issue->hasPainBugType()): ?> style="display: none;"<?php endif; ?>>
				<?php echo ($issue->hasPainBugType()) ? $issue->getPainBugTypeLabel() : ''; ?>
			</span>
			<span class="faded_out" id="no_pain_bug_type"<?php if ($issue->hasPainBugType()): ?> style="display: none;"<?php endif; ?>><?php echo __('Not triaged'); ?></span>
		</dd>
	</dl>
	<?php if ($issue->isEditable() && $issue->canEditUserPain()): ?>
		<div class="rounded_box white shadowed" id="pain_bug_type_change" style="display: none; width: 280px; position: absolute; z-index: 10001; margin: 5px 0 5px 0; padding: 5px;">
			<div class="dropdown_header"><?php echo __('Triage bug type'); ?></div>
			<div class="dropdown_content">
				<a href="javascript:void(0);" onclick="setField('<?php echo make_url('issue_setfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => 'pain_bug_type', 'pain_bug_type_id' => 0)); ?>', 'pain_bug_type');"><?php echo __('Clear bug type'); ?></a><br>
			</div>
			<div class="dropdown_content">
				<?php echo __('%clear_the_bugtype% or click to select a new bug type', array('%clear_the_bugtype%' => '')); ?>:<br>
				<ul class="choices">
					<?php foreach (TBGIssue::getPainTypesOrLabel('pain_bug_type') as $choice_id => $choice): ?>
						<li>
							<?php //echo image_tag('icon_' . $field . '.png', array('style' => 'float: left; margin-right: 5px;')); ?><a href="javascript:void(0);" onclick="setField('<?php echo make_url('issue_setfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => 'pain_bug_type', 'pain_bug_type_id' => $choice_id)); ?>', 'pain_bug_type');"><?php echo $choice; ?></a>
						</li>
					<?php endforeach; ?>
				</ul>
				<div id="pain_bug_type_spinning" style="margin-top: 3px; display: none;"><?php echo image_tag('spinning_20.gif', array('style' => 'float: left; margin-right: 5px;')) . '&nbsp;' . __('Please wait'); ?>...</div>
			</div>
			<div id="pain_bug_type_change_error" class="error_message" style="display: none;"></div>
		</div>
	<?php endif; ?>
	<dl class="viewissue_list" id="pain_likelihood_field">
		<dt id="pain_likelihood_header" class="<?php if ($issue->isPainLikelihoodChanged()): ?>issue_detail_changed<?php endif; ?><?php if (!$issue->isPainLikelihoodMerged()): ?> issue_detail_unmerged<?php endif; ?>"><?php echo __('Likelihood'); ?></dt>
		<dd id="pain_likelihood_content" class="<?php if ($issue->isPainLikelihoodChanged()): ?>issue_detail_changed<?php endif; ?><?php if (!$issue->isPainLikelihoodMerged()): ?> issue_detail_unmerged<?php endif; ?>">
			<?php if ($issue->isEditable() && $issue->canEditUserPain()): ?>
				<a href="javascript:void(0);" onclick="revertField('<?php echo make_url('issue_revertfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => 'pain_likelihood')); ?>', 'pain_likelihood');" title="<?php echo __('Undo this change'); ?>"><?php echo image_tag('undo.png', array('class' => 'undo')); ?></a>
				<?php echo image_tag('spinning_16.gif', array('style' => 'display: none; float: left; margin-right: 5px;', 'id' => 'pain_likelihood_undo_spinning')); ?>
				<a href="javascript:void(0);" onclick="$('pain_likelihood_change').toggle();" title="<?php echo __('Click to triage likelihood'); ?>"><?php echo image_tag('action_dropdown_small.png', array('class' => 'dropdown')); ?></a>
			<?php endif; ?>
			<span id="pain_likelihood_name"<?php if (!$issue->hasPainLikelihood()): ?> style="display: none;"<?php endif; ?>>
				<?php echo ($issue->hasPainLikelihood()) ? $issue->getPainLikelihoodLabel() : ''; ?>
			</span>
			<span class="faded_out" id="no_pain_likelihood"<?php if ($issue->hasPainLikelihood()): ?> style="display: none;"<?php endif; ?>><?php echo __('Not triaged'); ?></span>
		</dd>
	</dl>
	<?php if ($issue->isEditable() && $issue->canEditUserPain()): ?>
		<div class="rounded_box white shadowed" id="pain_likelihood_change" style="display: none; width: 280px; position: absolute; z-index: 10001; margin: 5px 0 5px 0; padding: 5px;">
			<div class="dropdown_header"><?php echo __('Triage likelihood'); ?></div>
			<div class="dropdown_content">
				<a href="javascript:void(0);" onclick="setField('<?php echo make_url('issue_setfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => 'pain_likelihood', 'pain_likelihood_id' => 0)); ?>', 'pain_likelihood');"><?php echo __('Clear likelihood'); ?></a><br>
			</div>
			<div class="dropdown_content">
				<?php echo __('%clear_the_likelihood% or click to select a new likelihood', array('%clear_the_likelihood%' => '')); ?>:<br>
				<ul class="choices">
					<?php foreach (TBGIssue::getPainTypesOrLabel('pain_likelihood') as $choice_id => $choice): ?>
						<li>
							<?php //echo image_tag('icon_' . $field . '.png', array('style' => 'float: left; margin-right: 5px;')); ?><a href="javascript:void(0);" onclick="setField('<?php echo make_url('issue_setfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => 'pain_likelihood', 'pain_likelihood_id' => $choice_id)); ?>', 'pain_likelihood');"><?php echo $choice; ?></a>
						</li>
					<?php endforeach; ?>
				</ul>
				<div id="pain_likelihood_spinning" style="margin-top: 3px; display: none;"><?php echo image_tag('spinning_20.gif', array('style' => 'float: left; margin-right: 5px;')) . '&nbsp;' . __('Please wait'); ?>...</div>
			</div>
			<div id="pain_likelihood_change_error" class="error_message" style="display: none;"></div>
		</div>
	<?php endif; ?>
	<dl class="viewissue_list" id="pain_effect_field">
		<dt id="pain_effect_header" class="<?php if ($issue->isPainEffectChanged()): ?>issue_detail_changed<?php endif; ?><?php if (!$issue->isPainEffectMerged()): ?> issue_detail_unmerged<?php endif; ?>"><?php echo __('Effect'); ?></dt>
		<dd id="pain_effect_content" class="<?php if ($issue->isPainEffectChanged()): ?>issue_detail_changed<?php endif; ?><?php if (!$issue->isPainEffectMerged()): ?> issue_detail_unmerged<?php endif; ?>">
			<?php if ($issue->isEditable() && $issue->canEditUserPain()): ?>
				<a href="javascript:void(0);" onclick="revertField('<?php echo make_url('issue_revertfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => 'pain_effect')); ?>', 'pain_effect');" title="<?php echo __('Undo this change'); ?>"><?php echo image_tag('undo.png', array('class' => 'undo')); ?></a>
				<?php echo image_tag('spinning_16.gif', array('style' => 'display: none; float: left; margin-right: 5px;', 'id' => 'pain_effect_undo_spinning')); ?>
				<a href="javascript:void(0);" onclick="$('pain_effect_change').toggle();" title="<?php echo __('Click to triage effect'); ?>"><?php echo image_tag('action_dropdown_small.png', array('class' => 'dropdown')); ?></a>
			<?php endif; ?>
			<span id="pain_effect_name"<?php if (!$issue->hasPainEffect()): ?> style="display: none;"<?php endif; ?>>
				<?php echo ($issue->hasPainEffect()) ? $issue->getPainEffectLabel() : ''; ?>
			</span>
			<span class="faded_out" id="no_pain_effect"<?php if ($issue->hasPainEffect()): ?> style="display: none;"<?php endif; ?>><?php echo __('Not triaged'); ?></span>
		</dd>
	</dl>
	<?php if ($issue->isEditable() && $issue->canEditUserPain()): ?>
		<div class="rounded_box white shadowed" id="pain_effect_change" style="display: none; width: 280px; position: absolute; z-index: 10001; margin: 5px 0 5px 0; padding: 5px;">
			<div class="dropdown_header"><?php echo __('Triage effect'); ?></div>
			<div class="dropdown_content">
				<a href="javascript:void(0);" onclick="setField('<?php echo make_url('issue_setfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => 'pain_effect', 'pain_effect_id' => 0)); ?>', 'pain_effect');"><?php echo __('Clear effect'); ?></a><br>
			</div>
			<div class="dropdown_content">
				<?php echo __('%clear_the_effect% or click to select a new effect', array('%clear_the_effect%' => '')); ?>:<br>
				<ul class="choices">
					<?php foreach (TBGIssue::getPainTypesOrLabel('pain_effect') as $choice_id => $choice): ?>
						<li>
							<?php //echo image_tag('icon_' . $field . '.png', array('style' => 'float: left; margin-right: 5px;')); ?><a href="javascript:void(0);" onclick="setField('<?php echo make_url('issue_setfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => 'pain_effect', 'pain_effect_id' => $choice_id)); ?>', 'pain_effect');"><?php echo $choice; ?></a>
						</li>
					<?php endforeach; ?>
				</ul>
				<div id="pain_effect_spinning" style="margin-top: 3px; display: none;"><?php echo image_tag('spinning_20.gif', array('style' => 'float: left; margin-right: 5px;')) . '&nbsp;' . __('Please wait'); ?>...</div>
			</div>
			<div id="pain_effect_change_error" class="error_message" style="display: none;"></div>
		</div>
	<?php endif; ?>
</div>
<dl class="viewissue_list" id="posted_by_field">
	<dt id="posted_by_header" class="<?php if ($issue->isPostedByChanged()): ?>issue_detail_changed<?php endif; ?><?php if (!$issue->isPostedByMerged()): ?> issue_detail_unmerged<?php endif; ?>"><?php echo __('Posted by'); ?></dt>
	<dd id="posted_by_content" class="<?php if ($issue->isPostedByChanged()): ?>issue_detail_changed<?php endif; ?><?php if (!$issue->isPostedByMerged()): ?> issue_detail_unmerged<?php endif; ?>">
		<?php if ($issue->isEditable() && $issue->canEditPostedBy()): ?>
			<a href="javascript:void(0);" onclick="revertField('<?php echo make_url('issue_revertfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => 'posted_by')); ?>', 'posted_by');" title="<?php echo __('Undo this change'); ?>"><?php echo image_tag('undo.png', array('class' => 'undo')); ?></a>
			<?php echo image_tag('spinning_16.gif', array('style' => 'display: none; float: left; margin-right: 5px;', 'id' => 'posted_by_undo_spinning')); ?>
			<a href="javascript:void(0);" onclick="$('posted_by_change').toggle();" title="<?php echo __('Click to change owner'); ?>"><?php echo image_tag('action_dropdown_small.png', array('class' => 'dropdown')); ?></a>
		<?php endif; ?>
		<div style="width: 170px; display: inline;" id="posted_by_name">
			<?php echo include_component('main/userdropdown', array('user' => $issue->getPostedBy())); ?>
		</div>
		<span id="no_posted_by" style="display: none;"> </span>
	</dd>
</dl>
<?php if ($issue->isEditable() && $issue->canEditPostedBy()): ?>
	<?php include_component('identifiableselector', array(	'html_id' 			=> 'posted_by_change', 
															'header' 			=> __('Change poster'),
															'allow_clear'		=> false,
															'clear_link_text'	=> '',
															'callback'		 	=> "setField('" . make_url('issue_setfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => 'posted_by', 'value' => '%identifiable_value%')) . "', 'posted_by');",
															'base_id'			=> 'posted_by',
															'absolute'			=> true)); ?>
<?php endif; ?>
<dl class="viewissue_list" id="owned_by_field">
	<dt id="owned_by_header" class="<?php if ($issue->isOwnedByChanged()): ?>issue_detail_changed<?php endif; ?><?php if (!$issue->isOwnedByMerged()): ?> issue_detail_unmerged<?php endif; ?>"><?php echo __('Owned by'); ?></dt>
	<dd id="owned_by_content" class="<?php if ($issue->isOwnedByChanged()): ?>issue_detail_changed<?php endif; ?><?php if (!$issue->isOwnedByMerged()): ?> issue_detail_unmerged<?php endif; ?>">
		<?php if ($issue->isUpdateable() && $issue->canEditOwnedBy()): ?>
			<a href="javascript:void(0);" onclick="revertField('<?php echo make_url('issue_revertfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => 'owned_by')); ?>', 'owned_by');" title="<?php echo __('Undo this change'); ?>"><?php echo image_tag('undo.png', array('class' => 'undo')); ?></a>
			<?php echo image_tag('spinning_16.gif', array('style' => 'display: none; float: left; margin-right: 5px;', 'id' => 'owned_by_undo_spinning')); ?>
			<a href="javascript:void(0);" onclick="$('owned_by_change').toggle();" title="<?php echo __('Click to change owner'); ?>"><?php echo image_tag('action_dropdown_small.png', array('class' => 'dropdown')); ?></a>
		<?php endif; ?>
		<div style="width: 170px; display: <?php if ($issue->isOwned()): ?>inline<?php else: ?>none<?php endif; ?>;" id="owned_by_name">
			<?php if ($issue->getOwnerType() == TBGIdentifiableClass::TYPE_USER): ?>
				<?php echo include_component('main/userdropdown', array('user' => $issue->getOwner())); ?>
			<?php elseif ($issue->getOwnerType() == TBGIdentifiableClass::TYPE_TEAM): ?>
				<?php echo include_component('main/teamdropdown', array('team' => $issue->getOwner())); ?>
			<?php endif; ?>
		</div>
		<span class="faded_out" id="no_owned_by"<?php if ($issue->isOwned()): ?> style="display: none;"<?php endif; ?>><?php echo __('Not owned by anyone'); ?></span>
	</dd>
</dl>
<?php if ($issue->isUpdateable() && $issue->canEditOwnedBy()): ?>
	<?php include_component('identifiableselector', array(	'html_id' 			=> 'owned_by_change', 
															'header' 			=> __('Change issue owner'),
															'callback'		 	=> "setField('" . make_url('issue_setfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => 'owned_by', 'identifiable_type' => '%identifiable_type%', 'value' => '%identifiable_value%')) . "', 'owned_by');",
															'teamup_callback'	=> "setField('" . make_url('issue_setfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => 'owned_by', 'identifiable_type' => '%identifiable_type%', 'value' => '%identifiable_value%', 'teamup' => true)) . "', 'owned_by');",
															'clear_link_text'	=> __('Clear current owner'),
															'base_id'			=> 'owned_by',
															'include_teams'		=> true,
															'absolute'			=> true)); ?>
<?php endif; ?>
<dl class="viewissue_list" id="estimated_time_field"<?php if (!$issue->isEstimatedTimeVisible()): ?> style="display: none;"<?php endif; ?>>
	<dt id="estimated_time_header" class="<?php if ($issue->isEstimatedTimeChanged()): ?>issue_detail_changed<?php endif; ?><?php if (!$issue->isEstimatedTimeMerged()): ?> issue_detail_unmerged<?php endif; ?>"><?php echo __('Estimated time'); ?></dt>
	<dd id="estimated_time_content" class="<?php if ($issue->isEstimatedTimeChanged()): ?>issue_detail_changed<?php endif; ?><?php if (!$issue->isEstimatedTimeMerged()): ?> issue_detail_unmerged<?php endif; ?>">
		<?php if ($issue->isUpdateable() && $issue->canEditEstimatedTime()): ?>
			<a href="javascript:void(0);" onclick="revertField('<?php echo make_url('issue_revertfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => 'estimated_time')); ?>', 'estimated_time');" title="<?php echo __('Undo this change'); ?>"><?php echo image_tag('undo.png', array('class' => 'undo')); ?></a>
			<?php echo image_tag('spinning_16.gif', array('style' => 'display: none; float: left; margin-right: 5px;', 'id' => 'estimated_time_undo_spinning')); ?>
			<a href="javascript:void(0);" onclick="$('estimated_time_change').toggle();" title="<?php echo __('Click to estimate this issue'); ?>"><?php echo image_tag('action_dropdown_small.png', array('class' => 'dropdown')); ?></a>
		<?php endif; ?>
		<span id="estimated_time_name"<?php if (!$issue->hasEstimatedTime()): ?> style="display: none;"<?php endif; ?>>
			<?php echo $issue->getFormattedTime($issue->getEstimatedTime()); ?>
		</span>
		<span class="faded_out" id="no_estimated_time"<?php if ($issue->hasEstimatedTime()): ?> style="display: none;"<?php endif; ?>><?php echo __('Not estimated'); ?></span>
	</dd>
</dl>
<?php if ($issue->isUpdateable() && $issue->canEditEstimatedTime()): ?>
	<div class="rounded_box white shadowed" id="estimated_time_change" style="display: none; width: 280px; position: absolute; z-index: 10001; margin: 5px 0 5px 0; padding: 5px;">
		<form id="estimated_time_form" method="post" accept-charset="<?php echo TBGContext::getI18n()->getCharset(); ?>" action="" onsubmit="setTimeField('<?php echo make_url('issue_setfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => 'estimated_time')); ?>', 'estimated_time');return false;">
			<div class="dropdown_header"><?php echo __('Estimate this issue'); ?></div>
			<div class="dropdown_content">
				<a href="javascript:void(0);" onclick="setField('<?php echo make_url('issue_setfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => 'estimated_time', 'value' => 0)); ?>', 'estimated_time');"><?php echo __('Clear current estimate'); ?></a><br>
			</div>
			<div class="dropdown_content">
				<label for="estimated_time_input"><?php echo trim(__('%clear_current_estimate% type a new estimate %or_select_below%', array('%clear_current_estimate%' => '', '%or_select_below%' => ''))); ?>:</label><br>
				<?php $estimated_time_title = __('Enter your estimate here'); ?>
				<input type="text" name="estimated_time" id="estimated_time_input" value="<?php echo $estimated_time_title; ?>" style="width: 240px; padding: 1px 1px 1px;" onblur="if (this.getValue() == '') { this.value = '<?php echo $estimated_time_title; ?>'; this.addClassName('faded_out'); }" onfocus="if (this.getValue() == '<?php echo $estimated_time_title; ?>') { this.clear(); } this.removeClassName('faded_out');" class="faded_out">
				<input type="submit" style="width: 60px;" value="<?php echo __('Estimate'); ?>">
				<div class="faded_out" style="padding: 5px 0 5px 0;"><?php echo __('Enter an estimate in plain text, like "1 week, 2 hours", "3 months and 1 day", or similar'); ?>.</div>
			</div>
			<div class="dropdown_content">
				<label for="estimated_time_months"><?php echo __('or enter an estimate below'); ?>:</label><br>
				<input type="text" style="width: 20px;" value="<?php echo $issue->getEstimatedMonths(); ?>" name="estimated_time_months" id="estimated_time_months"><b><?php echo __('%number_of% months', array('%number_of%' => '')); ?></b><br>
				<input type="text" style="width: 20px;" value="<?php echo $issue->getEstimatedWeeks(); ?>" name="estimated_time_weeks" id="estimated_time_weeks"><b><?php echo __('%number_of% weeks', array('%number_of%' => '')); ?></b><br>
				<input type="text" style="width: 20px;" value="<?php echo $issue->getEstimatedDays(); ?>" name="estimated_time_days" id="estimated_time_days"><b><?php echo __('%number_of% days', array('%number_of%' => '')); ?></b><br>
				<input type="text" style="width: 20px;" value="<?php echo $issue->getEstimatedHours(); ?>" name="estimated_time_hours" id="estimated_time_hours"><b><?php echo __('%number_of% hours', array('%number_of%' => '')); ?></b><br>
				<input type="submit" style="width: 60px; float: right;" value="<?php echo __('Estimate'); ?>">
				<input type="text" style="width: 20px;" value="<?php echo $issue->getEstimatedPoints(); ?>" name="estimated_time_points" id="estimated_time_points"><b><?php echo __('%number_of% points', array('%number_of%' => '')); ?></b><br>
			</div>
		</form>
		<div id="estimated_time_spinning" style="margin-top: 3px; display: none;"><?php echo image_tag('spinning_20.gif', array('style' => 'float: left; margin-right: 5px;')) . '&nbsp;' . __('Please wait'); ?>...</div>
		<div id="estimated_time_change_error" class="error_message" style="display: none;"></div>
	</div>
<?php endif; ?>
<dl class="viewissue_list" id="spent_time_field"<?php if (!$issue->isSpentTimeVisible()): ?> style="display: none;"<?php endif; ?>>
	<dt id="spent_time_header" class="<?php if ($issue->isSpentTimeChanged()): ?>issue_detail_changed<?php endif; ?><?php if (!$issue->isSpentTimeMerged()): ?> issue_detail_unmerged<?php endif; ?>"><?php echo __('Time spent'); ?></dt>
	<dd id="spent_time_content" class="<?php if ($issue->isSpentTimeChanged()): ?>issue_detail_changed<?php endif; ?><?php if (!$issue->isSpentTimeMerged()): ?> issue_detail_unmerged<?php endif; ?>">
		<?php if ($issue->isUpdateable() && $issue->canEditSpentTime()): ?>
			<a href="javascript:void(0);" onclick="revertField('<?php echo make_url('issue_revertfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => 'spent_time')); ?>', 'spent_time');" title="<?php echo __('Undo this change'); ?>"><?php echo image_tag('undo.png', array('class' => 'undo')); ?></a>
			<?php echo image_tag('spinning_16.gif', array('style' => 'display: none; float: left; margin-right: 5px;', 'id' => 'spent_time_undo_spinning')); ?>
			<a href="javascript:void(0);" onclick="$('spent_time_change').toggle();" title="<?php echo __('Click to enter time spent on this issue'); ?>"><?php echo image_tag('action_dropdown_small.png', array('class' => 'dropdown')); ?></a>
		<?php endif; ?>
		<span id="spent_time_name"<?php if (!$issue->hasSpentTime()): ?> style="display: none;"<?php endif; ?>>
			<?php echo $issue->getFormattedTime($issue->getSpentTime()); ?>
		</span>
		<span class="faded_out" id="no_spent_time"<?php if ($issue->hasSpentTime()): ?> style="display: none;"<?php endif; ?>><?php echo __('No time spent'); ?></span>
	</dd>
</dl>
<?php if ($issue->isUpdateable() && $issue->canEditSpentTime()): ?>
	<div class="rounded_box white shadowed" id="spent_time_change" style="display: none; width: 280px; position: absolute; z-index: 10001; margin: 5px 0 5px 0; padding: 5px;">
		<form id="spent_time_form" method="post" accept-charset="<?php echo TBGContext::getI18n()->getCharset(); ?>" action="" onsubmit="setTimeField('<?php echo make_url('issue_setfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => 'spent_time')); ?>', 'spent_time');return false;">
			<div class="dropdown_header"><?php echo __('Set time spent on this issue'); ?></div>
			<div class="dropdown_content">
				<a href="javascript:void(0);" onclick="setField('<?php echo make_url('issue_setfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => 'spent_time', 'value' => 0)); ?>', 'spent_time');"><?php echo __('Clear time spent on this issue'); ?></a><br>
			</div>
			<div class="dropdown_content">
				<label for="spent_time_input"><?php echo trim(__("%clear_time_spent% enter how much time you've spent %or_select_below%", array('%clear_time_spent%' => '', '%or_select_below%' => ''))); ?>:</label><br>
				<?php $spent_time_title = __('Enter time spent here'); ?>
				<input type="text" name="spent_time" id="spent_time_input" value="<?php echo $spent_time_title; ?>" style="width: 180px; padding: 1px 1px 1px;" onblur="if (this.getValue() == '') { this.value = '<?php echo $spent_time_title; ?>'; this.addClassName('faded_out'); }" onfocus="if (this.getValue() == '<?php echo $spent_time_title; ?>') { this.clear(); } this.removeClassName('faded_out');" class="faded_out">
				<input type="submit" style="width: 80px;" value="<?php echo __('Spend time'); ?>"><br>
				<input type="checkbox" checked="checked" name="spent_time_added_text" value="true" id="spent_time_added_text"><label for="spent_time_added_text"><?php echo __('Add entered time to total time spent') ?></label>
				<div class="faded_out" style="padding: 5px 0 5px 0;"><?php echo __('Enter time spent as plain text, like "1 day, 2 hours", "12 hours / 2 points", or similar'); ?>.</div>
			</div>
			<div class="dropdown_content">
				<label for="spent_time_months"><?php echo __('or enter time spent below'); ?>:</label><br>
				<input type="text" style="width: 20px;" value="<?php echo $issue->getSpentMonths(); ?>" name="spent_time_months" id="spent_time_months"><b><?php echo __('%number_of% months', array('%number_of%' => '')); ?></b><br>
				<input type="text" style="width: 20px;" value="<?php echo $issue->getSpentWeeks(); ?>" name="spent_time_weeks" id="spent_time_weeks"><b><?php echo __('%number_of% weeks', array('%number_of%' => '')); ?></b><br>
				<input type="text" style="width: 20px;" value="<?php echo $issue->getSpentDays(); ?>" name="spent_time_days" id="spent_time_days"><b><?php echo __('%number_of% days', array('%number_of%' => '')); ?></b><br>
				<input type="text" style="width: 20px;" value="<?php echo $issue->getSpentHours(); ?>" name="spent_time_hours" id="spent_time_hours"><b><?php echo __('%number_of% hours', array('%number_of%' => '')); ?></b><br>
				<input type="submit" style="width: 80px; float: right;" value="<?php echo __('Spend time'); ?>">
				<input type="text" style="width: 20px;" value="<?php echo $issue->getSpentPoints(); ?>" name="spent_time_points" id="spent_time_points"><b><?php echo __('%number_of% points', array('%number_of%' => '')); ?></b><br>
				<input type="checkbox" name="spent_time_added_input" value="true" id="spent_time_added_input"><label for="spent_time_added_text"><?php echo __('Add entered time to total time spent') ?></label>
			</div>
		</form>
		<div id="spent_time_spinning" style="margin-top: 3px; display: none;"><?php echo image_tag('spinning_20.gif', array('style' => 'float: left; margin-right: 5px;')) . '&nbsp;' . __('Please wait'); ?>...</div>
		<div id="spent_time_change_error" class="error_message" style="display: none;"></div>
	</div>
<?php endif; ?>
<?php foreach ($fields_list as $field => $info): ?>
	<dl class="viewissue_list" id="<?php echo $field; ?>_field"<?php if (!$info['visible']): ?> style="display: none;"<?php endif; ?>>
		<dt id="<?php echo $field; ?>_header" class="<?php if ($info['changed']): ?>issue_detail_changed<?php endif; ?><?php if (!$info['merged']): ?> issue_detail_unmerged<?php endif; ?>">
			<?php echo $info['title']; ?>
		</dt>
		<dd id="<?php echo $field; ?>_content" class="<?php if ($info['changed']): ?>issue_detail_changed<?php endif; ?><?php if (!$info['merged']): ?> issue_detail_unmerged<?php endif; ?>">
			<?php if (array_key_exists('choices', $info) && isset($info['choices'])): ?>
				<a href="javascript:void(0);" onclick="revertField('<?php echo make_url('issue_revertfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => $field)); ?>', '<?php echo $field; ?>');" title="<?php echo __('Undo this change'); ?>"><?php echo image_tag('undo.png', array('class' => 'undo')); ?></a>
				<?php echo image_tag('spinning_16.gif', array('style' => 'display: none; float: left; margin-right: 5px;', 'id' => $field . '_undo_spinning')); ?>
				<a href="javascript:void(0);" onclick="$('<?php echo $field; ?>_change').toggle();" title="<?php echo $info['change_tip']; ?>"><?php echo image_tag('action_dropdown_small.png', array('class' => 'dropdown')); ?></a>
			<?php endif; ?>
			<?php if ($info['icon']): ?>
				<?php echo image_tag($info['icon_name'], array('style' => 'float: left; margin-right: 5px;')); ?>
			<?php endif; ?>
			<span id="<?php echo $field; ?>_name"<?php if (!$info['name_visible']): ?> style="display: none;"<?php endif; ?>><?php echo $info['name']; ?></span>
			<span class="faded_out" id="no_<?php echo $field; ?>"<?php if (!$info['noname_visible']): ?> style="display: none;"<?php endif; ?>><?php echo __('Not determined'); ?></span>
		</dd>
	</dl>
	<div style="clear: both;"> </div>
	<?php if (array_key_exists('choices', $info) && isset($info['choices'])): ?>
		<div class="rounded_box white shadowed" id="<?php echo $field; ?>_change" style="display: none; width: 280px; position: absolute; z-index: 10001; margin: 5px 0 5px 0; padding: 5px;">
			<div class="dropdown_header"><?php echo $info['change_header']; ?></div>
			<div class="dropdown_content">
				<a href="javascript:void(0);" onclick="setField('<?php echo make_url('issue_setfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => $field, $field . '_id' => 0)); ?>', '<?php echo $field; ?>');"><?php echo $info['clear']; ?></a><br>
			</div>
			<div class="dropdown_content">
				<?php echo $info['select']; ?>:<br>
				<ul class="choices">
					<?php foreach ($info['choices'] as $choice): ?>
						<?php if ($choice instanceof TBGDatatypeBase && !$choice->canUserSet($tbg_user)) continue; ?>
						<li>
							<?php echo image_tag('icon_' . $field . '.png', array('style' => 'float: left; margin-right: 5px;')); ?><a href="javascript:void(0);" onclick="setField('<?php echo make_url('issue_setfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => $field, $field . '_id' => $choice->getID())); ?>', '<?php echo $field; ?>');"><?php echo $choice->getName(); ?></a>
						</li>
					<?php endforeach; ?>
				</ul>
				<div id="<?php echo $field; ?>_spinning" style="margin-top: 3px; display: none;"><?php echo image_tag('spinning_20.gif', array('style' => 'float: left; margin-right: 5px;')) . '&nbsp;' . __('Please wait'); ?>...</div>
			</div>
			<div id="<?php echo $field; ?>_change_error" class="error_message" style="display: none;"></div>
		</div>
	<?php endif; ?>
<?php endforeach; ?>
<?php foreach ($customfields_list as $field => $info): ?>
	<?php if ($info['type'] == TBGCustomDatatype::INPUT_TEXTAREA_MAIN): continue; endif; ?>
	<dl class="viewissue_list" id="<?php echo $field; ?>_field"<?php if (!$info['visible']): ?> style="display: none;"<?php endif; ?>>
		<dt id="<?php echo $field; ?>_header" class="<?php if ($info['changed']): ?>issue_detail_changed<?php endif; ?><?php if (!$info['merged']): ?> issue_detail_unmerged<?php endif; ?>">
			<?php echo $info['title']; ?>
		</dt>
		<dd id="<?php echo $field; ?>_content" class="<?php if ($info['changed']): ?>issue_detail_changed<?php endif; ?><?php if (!$info['merged']): ?> issue_detail_unmerged<?php endif; ?>">
			<?php if ($issue->isEditable()): ?>
				<a href="javascript:void(0);" onclick="revertField('<?php echo make_url('issue_revertfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => $field)); ?>', '<?php echo $field; ?>');" title="<?php echo __('Undo this change'); ?>"><?php echo image_tag('undo.png', array('class' => 'undo')); ?></a>
				<?php echo image_tag('spinning_16.gif', array('style' => 'display: none; float: left; margin-right: 5px;', 'id' => $field . '_undo_spinning')); ?>
				<a href="javascript:void(0);" onclick="$('<?php echo $field; ?>_change').toggle();" title="<?php echo $info['change_tip']; ?>"><?php echo image_tag('action_dropdown_small.png', array('class' => 'dropdown')); ?></a>
			<?php endif; ?>
			<?php echo image_tag('icon_customdatatype.png', array('style' => 'float: left; margin-right: 5px;')); ?>
			<?php 
				switch ($info['type'])
				{
					case TBGCustomDatatype::INPUT_TEXTAREA_SMALL:
						?><span id="<?php echo $field; ?>_name"<?php if (!$info['name_visible']): ?> style="display: none;"<?php endif; ?>><?php echo tbg_parse_text($info['name'], false, null, array('headers' => false)); ?></span><span class="faded_out" id="no_<?php echo $field; ?>"<?php if (!$info['noname_visible']): ?> style="display: none;"<?php endif; ?>><?php echo __('Not determined'); ?></span><?php
						break;
					case TBGCustomDatatype::EDITIONS_CHOICE:
					case TBGCustomDatatype::COMPONENTS_CHOICE:
					case TBGCustomDatatype::RELEASES_CHOICE:
						$edition = null;
						$value = null;
						try
						{
							switch ($info['type'])
							{
								case TBGCustomDatatype::EDITIONS_CHOICE:
									$edition = new TBGEdition($info['name']);
									$value = $edition->getName();
									break;
								case TBGCustomDatatype::COMPONENTS_CHOICE:
									$edition = new TBGComponent($info['name']);
									$value = $edition->getName();
									break;
								case TBGCustomDatatype::RELEASES_CHOICE:
									$edition = new TBGBuild($info['name']);
									$value = $edition->getName();
									break;
							}
						}
						catch (Exception $e) { }
						?><span id="<?php echo $field; ?>_name"<?php if (!$info['name_visible']): ?> style="display: none;"<?php endif; ?>><?php echo $value; ?></span><span class="faded_out" id="no_<?php echo $field; ?>"<?php if (!$info['noname_visible']): ?> style="display: none;"<?php endif; ?>><?php echo __('Not determined'); ?></span><?php
						break;
					case TBGCustomDatatype::STATUS_CHOICE:
						$status = null;
						$value = null;
						$color = '#FFF';
						try
						{
							$status = new TBGStatus($info['name']);
							$value = $status->getName();
							$color = $status->getColor();
						}
						catch (Exception $e) { }
						?><span id="<?php echo $field; ?>_name"<?php if (!$info['name_visible']): ?> style="display: none;"<?php endif; ?>><div style="border: 1px solid #AAA; background-color: <?php echo $color; ?>; font-size: 1px; width: 20px; height: 15px; margin-right: 5px; float: left;" id="status_color">&nbsp;</div><?php echo $value; ?></span><span class="faded_out" id="no_<?php echo $field; ?>"<?php if (!$info['noname_visible']): ?> style="display: none;"<?php endif; ?>><?php echo __('Not determined'); ?></span><?php
						break;
					default:
						?><span id="<?php echo $field; ?>_name"<?php if (!$info['name_visible']): ?> style="display: none;"<?php endif; ?>><?php echo $info['name']; ?></span><span class="faded_out" id="no_<?php echo $field; ?>"<?php if (!$info['noname_visible']): ?> style="display: none;"<?php endif; ?>><?php echo __('Not determined'); ?></span><?php
						break;
				}
			?>
		</dd>
	</dl>
	<div style="clear: both;"> </div>
	<?php if ($issue->isEditable()): ?>
		<div class="rounded_box white shadowed" id="<?php echo $field; ?>_change" style="display: none; width: 280px; position: absolute; z-index: 10001; margin: 5px 0 5px 0; padding: 5px;">
			<div class="dropdown_header"><?php echo $info['change_header']; ?></div>
				<?php echo $info['select']; ?>:<br>
				<?php if (array_key_exists('choices', $info)): ?>
					<a href="javascript:void(0);" onclick="setField('<?php echo make_url('issue_setfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => $field, $field . '_value' => "")); ?>', '<?php echo $field; ?>');"><?php echo $info['clear']; ?></a><br>
					<ul class="choices">
						<?php foreach ($info['choices'] as $choice): ?>
							<?php if (!$choice->canUserSet($tbg_user)) continue; ?>
							<li>
								<?php echo image_tag('icon_customdatatype.png', array('style' => 'float: left; margin-right: 5px;')); ?><a href="javascript:void(0);" onclick="setField('<?php echo make_url('issue_setfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => $field, $field . '_value' => $choice->getValue())); ?>', '<?php echo $field; ?>');"><?php echo $choice->getName(); ?></a>
							</li>
						<?php endforeach; ?>
					</ul>
				<?php else:

					switch ($info['type'])
					{
						case TBGCustomDatatype::EDITIONS_CHOICE:
							?>
								<a href="javascript:void(0);" onclick="setField('<?php echo make_url('issue_setfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => $field, $field . '_value' => "")); ?>', '<?php echo $field; ?>');"><?php echo $info['clear']; ?></a><br>
								<ul class="choices">
									<?php foreach (TBGEdition::getAllByProjectID($issue->getProject()->getID()) as $choice): ?>
										<li>
											<?php echo image_tag('icon_edition.png', array('style' => 'float: left; margin-right: 5px;')); ?><a href="javascript:void(0);" onclick="setField('<?php echo make_url('issue_setfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => $field, $field . '_value' => $choice->getID())); ?>', '<?php echo $field; ?>');"><?php echo $choice->getName(); ?></a>
										</li>
									<?php endforeach; ?>
								</ul>
							<?php
							break;
						case TBGCustomDatatype::STATUS_CHOICE:
							?>
								<a href="javascript:void(0);" onclick="setField('<?php echo make_url('issue_setfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => $field, $field . '_value' => "")); ?>', '<?php echo $field; ?>');"><?php echo $info['clear']; ?></a><br>
								<ul class="choices">
									<?php foreach (TBGStatus::getAll($issue->getProject()->getID()) as $choice): ?>
										<li>
											<div style="border: 1px solid #AAA; background-color: <?php echo $choice->getColor(); ?>; font-size: 1px; width: 20px; height: 15px; margin-right: 7px; float: left;" id="status_color">&nbsp;</div><a href="javascript:void(0);" onclick="setField('<?php echo make_url('issue_setfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => $field, $field . '_value' => $choice->getID())); ?>', '<?php echo $field; ?>');"><?php echo $choice->getName(); ?></a>
										</li>
									<?php endforeach; ?>
								</ul>
							<?php
							break;
						case TBGCustomDatatype::COMPONENTS_CHOICE:
							?>
								<a href="javascript:void(0);" onclick="setField('<?php echo make_url('issue_setfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => $field, $field . '_value' => "")); ?>', '<?php echo $field; ?>');"><?php echo $info['clear']; ?></a><br>
								<ul class="choices">
									<?php foreach (TBGComponent::getAllByProjectID($issue->getProject()->getID()) as $choice): ?>
										<li>
											<?php echo image_tag('icon_components.png', array('style' => 'float: left; margin-right: 5px;')); ?><a href="javascript:void(0);" onclick="setField('<?php echo make_url('issue_setfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => $field, $field . '_value' => $choice->getID())); ?>', '<?php echo $field; ?>');"><?php echo $choice->getName(); ?></a>
										</li>
									<?php endforeach; ?>
								</ul>
							<?php
							break;
						case TBGCustomDatatype::RELEASES_CHOICE:
							?>
								<a href="javascript:void(0);" onclick="setField('<?php echo make_url('issue_setfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => $field, $field . '_value' => "")); ?>', '<?php echo $field; ?>');"><?php echo $info['clear']; ?></a><br>
								<ul class="choices">
									<?php foreach (TBGBuild::getByProjectID($issue->getProject()->getID()) as $choice): ?>
										<li>
											<?php echo image_tag('icon_build.png', array('style' => 'float: left; margin-right: 5px;')); ?><a href="javascript:void(0);" onclick="setField('<?php echo make_url('issue_setfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => $field, $field . '_value' => $choice->getID())); ?>', '<?php echo $field; ?>');"><?php echo $choice->getName(); ?></a>
										</li>
									<?php endforeach; ?>
								</ul>
							<?php
							break;
						case TBGCustomDatatype::INPUT_TEXT:
							?>
								<a href="javascript:void(0);" onclick="setField('<?php echo make_url('issue_setfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => $field, $field . '_value' => "")); ?>', '<?php echo $field; ?>');"><?php echo $info['clear']; ?></a><br>
								<form id="<?php echo $field; ?>_form" action="<?php echo make_url('issue_setfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => $field)); ?>" method="post" onSubmit="setField('<?php echo make_url('issue_setfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => $field)) ?>', '<?php echo $field; ?>', '<?php echo $field; ?>'); return false;">
									<input type="text" name="<?php echo $field; ?>_value" value="<?php echo $info['name'] ?>" /><?php echo __('%save% or %cancel%', array('%save%' => '<input type="submit" value="'.__('Save').'">', '%cancel%' => '<a href="#" onClick="$(\''.$field.'_change\').hide(); return false;">'.__('cancel').'</a>')); ?>
								</form>
							<?php
							break;
						case TBGCustomDatatype::INPUT_TEXTAREA_SMALL:
							?>
								<a href="javascript:void(0);" onclick="setField('<?php echo make_url('issue_setfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => $field, $field . '_value' => "")); ?>', '<?php echo $field; ?>');"><?php echo $info['clear']; ?></a><br>
								<form id="<?php echo $field; ?>_form" action="<?php echo make_url('issue_setfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => $field)); ?>" method="post" onSubmit="setField('<?php echo make_url('issue_setfield', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getID(), 'field' => $field)) ?>', '<?php echo $field; ?>', '<?php echo $field; ?>'); return false;">
									<?php include_template('main/textarea', array('area_name' => $field.'_value', 'area_id' => $field.'_value', 'height' => '100px', 'width' => '100%', 'value' => $info['name'])); ?>
									<br><?php echo __('%save% or %cancel%', array('%save%' => '<input type="submit" value="'.__('Save').'">', '%cancel%' => '<a href="#" onClick="$(\''.$field.'_change\').hide(); return false;">'.__('cancel').'</a>')); ?>
								</form>
							<?php
							break;
					}

				endif; ?>
				<div id="<?php echo $field; ?>_spinning" style="margin-top: 3px; display: none;"><?php echo image_tag('spinning_20.gif', array('style' => 'float: left; margin-right: 5px;')) . '&nbsp;' . __('Please wait'); ?>...</div>
			<div id="<?php echo $field; ?>_change_error" class="error_message" style="display: none;"></div>
		</div>
	<?php endif; ?>
<?php endforeach; ?>
<?php if (TBGContext::getUser()->hasPermission('caneditissue') || TBGContext::getUser()->hasPermission('caneditissuebasic')): ?>
<div style="clear: both; margin-bottom: 5px;"> </div>
<div id="more_actions" style="display: none;">
	<div class="rounded_box white shadowed">
		<div style="padding: 5px;">
			<ul>
				<?php if ($issue->isBlocking()): ?>
					<li><?php echo link_tag(make_url('unblock', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getId())), image_tag('icon_unblock.png', array('style' => 'float: left; margin-right: 5px;')) . __("Mark as not blocking the next release")); ?></li>
				<?php else: ?>
					<li><?php echo link_tag(make_url('block', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getId())), image_tag('icon_block.png', array('style' => 'float: left; margin-right: 5px;')) . __("Mark as blocking the next release")); ?></li>
				<?php endif; ?>
				<?php if (!$issue->isDuplicate()): ?>
					<li><a href="javascript:void(0);" onclick="showFadedBackdrop('<?php echo make_url('get_partial_for_backdrop', array('key' => 'markasduplicate_issue', 'issue_id' => $issue->getID())); ?>');"><?php echo image_tag('icon_duplicate_issues.png', array('style' => 'float: left; margin-right: 5px;')); ?><?php echo __('Mark this issue as a duplicate of another'); ?></a></li>
				<?php else: ?>
					<li><a href="javascript:void(0);" onclick="showFadedBackdrop('<?php echo make_url('get_partial_for_backdrop', array('key' => 'markasduplicate_issue', 'issue_id' => $issue->getID())); ?>');"><?php echo image_tag('icon_duplicate_issues.png', array('style' => 'float: left; margin-right: 5px;')); ?><?php echo __('Change the issue this is a duplicate of'); ?></a></li>
					<li><?php echo link_tag(make_url('notduplicate', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getId())), image_tag('icon_duplicate_issues.png', array('style' => 'float: left; margin-right: 5px;')) . __("Unmark this issue as a duplicate")); ?></li>
				<?php endif; ?>
				<li><a href="javascript:void(0)" onClick="$('move_issue').toggle();"><?php echo image_tag('icon_move.png', array('style' => 'float: left; margin-right: 5px;')) . __("Move issue to another project"); ?></a></li>
				<li style="display: none;" id="move_issue">
					<form action="<?php echo make_url('move_issue', array('issue_id' => $issue->getID())); ?>" method="post">
						<div class="rounded_box borderless yellow" style="margin: 5px 0 20px 0;">
							<b><?php echo __('Move issue to a different project'); ?></b>
							<p><?php echo __('Please be aware that moving this issue to a different project will reset details such as status, category, etc., and may also make some fields invisible, depending on the issue type configuration for that project.'); ?></p>
							<br>
							<label for="move_issue_project"><?php echo __('Move issue to'); ?></label><br>
							<select name="project_id">
								<?php foreach (TBGProject::getAll() as $project): ?>
									<?php if (!$tbg_user->canReportIssues($project) && $project->getID() != $issue->getProject()->getID()) continue; ?>
									<option value="<?php echo $project->getID(); ?>"<?php if ($project->getID() == $issue->getProject()->getID()): ?> selected<?php endif; ?>><?php echo $project->getName(); ?></option>
								<?php endforeach; ?>
							</select>
							<div style="text-align: right; padding-top: 5px;">
								<input type="submit" value="<?php echo __('Move issue'); ?>" onclick="$(this).hide();$('move_issue_indicator').show();">
								<?php echo image_tag('spinning_16.gif', array('id' => 'move_issue_indicator', 'style' => 'display: none; margin-right: 5px;')); ?>
								<?php echo __('%move_issue% or %cancel%', array('%move_issue%' => '', '%cancel%' => '')); ?>
								<a href="javascript:void(0)" onclick="$('move_issue').hide();"><?php echo __('cancel'); ?></a>
							</div>
						</div>
					</form>
				</li>
				<?php if (TBGContext::getUser()->hasPermission('candeleteissues')): ?>
					<li><a href="javascript:void(0)" onClick="$('delete_issue').toggle();"><?php echo image_tag('icon_delete.png', array('style' => 'float: left; margin-right: 5px;')) . __("Permanently delete this issue"); ?></a></li>
				<?php endif; ?>
			</ul>
			<div class="rounded_box borderless red" style="display: none;" id="delete_issue"> 
				<b><?php echo __('Permanently delete this issue'); ?></b>
				<p><?php echo __('Are you sure you wish to delete this issue? It will remain in the database for your records, but will not be accessible via The Bug Genie.'); ?></p>
				<?php echo link_tag(make_url('deleteissue', array('project_key' => $issue->getProject()->getKey(), 'issue_id' => $issue->getId())), __('Yes')); ?> | <a href="javascript:void(0)" onClick="$('delete_issue').hide();"><?php echo __('No'); ?></a>
			</div>
		</div>
	</div>
	<div style="text-align: center; font-size: 14px; width: 200px; margin: 5px auto 0 auto; padding: 5px 0 5px 0; height: 20px;">
		<a href="javascript:void(0);" onclick="$('more_actions').hide();$('more_actions_div').show();"><?php echo image_tag('action_remove_small.png', array('style' => 'float: left; margin-right: 5px;')); ?><span style="float: left;"><?php echo __('Hide further actions'); ?></span></a>
	</div>
</div>
<div style="text-align: center; font-size: 14px; width: 200px; margin: 5px auto 0 auto; padding: 5px 0 5px 0; height: 20px;" id="more_actions_div">
	<a href="javascript:void(0);" onclick="$('more_actions').show();$('more_actions_div').hide();"><?php echo image_tag('action_add_small_faded.png', array('style' => 'float: left; margin-right: 5px;')); ?><span style="float: left; font-weight: bold;"><?php echo __('Show further actions'); ?></span></a>
</div>
<?php endif; ?>