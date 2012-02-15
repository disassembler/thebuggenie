<div class="<?php if ($issue->getIssueType()->getIcon() == 'task'): ?>user_story_task<?php else: ?>related_issue<?php endif; ?>">
	<table style="table-layout: fixed; width: 100%;" cellpadding=0 cellspacing=0>
		<tr>
			<td style="width: 20px;"><div style="border: 1px solid #AAA; background-color: <?php echo ($issue->getStatus() instanceof TBGStatus) ? $issue->getStatus()->getColor() : '#FFF'; ?>; font-size: 1px; width: 13px; height: 13px;" title="<?php echo ($issue->getStatus() instanceof TBGStatus) ? $issue->getStatus()->getName() : ''; ?>">&nbsp;</div></td>
			<td style="padding: 1px; width: auto;" valign="middle"><?php echo link_tag(make_url('viewissue', array('issue_no' => $issue->getFormattedIssueNo(), 'project_key' => $issue->getProject()->getKey())), (($issue->getIssueType()->isTask() ? $issue->getTitle() : $issue->getFormattedTitle()))); ?></td>
			<td style="padding: 1px; width: 20px;" valign="middle">
				<?php if ($issue->getState() == TBGIssue::STATE_CLOSED): ?>
					<?php echo image_tag('action_ok_small.png', array('title' => ($issue->getIssuetype()->isTask()) ? __('This relation is solved because the task has been closed') : __('This relation is solved because the issue has been closed'))); ?>
				<?php else: ?>
					<?php echo image_tag('action_cancel_small.png', array('title' => ($issue->getIssuetype()->isTask()) ? __('This task must be closed before the issue relation is solved') : __('This issue must be closed before the issue relation is solved'))); ?>
				<?php endif; ?>
			</td>
		</tr>
		<tr<?php if (!$issue->isAssigned()): ?> style="display: none;"<?php endif; ?>>
			<td colspan="3" valign="middle">
				<table border="0" cellpadding="0" cellspacing="0">
					<tr>
						<td valign="middle" class="faded_out">
						<?php if ($issue->isAssigned()): ?>
							<?php if ($issue->getAssignee() instanceof TBGUser): ?>
								<?php echo __('Assigned to %user%', array('%user%' => '</td><td style="padding-left: 5px;" class="faded_out">' . get_component_html('main/userdropdown', array('user' => $issue->getAssignee(), 'size' => 'small')))); ?>
							<?php elseif ($issue->getAssignee() instanceof TBGTeam): ?>
								<?php echo __('Assigned to %team%', array('%team%' => '</td><td style="padding-left: 5px;" class="faded_out">' . get_component_html('main/teamdropdown', array('team' => $issue->getAssignee(), 'size' => 'small')))); ?>
							<?php endif; ?>
						<?php endif; ?>
						</td>
					</tr>
				</table>
			</td>
		</tr>
	</table>
</div>