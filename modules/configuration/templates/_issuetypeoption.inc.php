<tr class="canhover_light" id="item_<?php echo $key; ?>_<?php echo $issuetype->getID(); ?>">
	<td style="padding: 2px; font-size: 12px;" id="<?php echo $key; ?>_<?php echo $issuetype->getID(); ?>_name">
		<?php
		
			if (is_object($item))
			{
				echo $item->getDescription();
			}
			else
			{
				switch ($item)
				{
					case 'description':
						echo __('Issue description');
						break;
					case 'reproduction_steps':
						echo __('Steps to reproduce the issue');
						break;
					case 'percent_complete':
						echo __('Percent completed');
						break;
					case 'builds':
						echo __('Affected release(s)');
						break;
					case 'components':
						echo __('Affected component(s)');
						break;
					case 'editions':
						echo __('Affected edition(s)');
						break;
					case 'estimated_time':
						echo __('Estimated time to complete');
						break;
					case 'elapsed_time':
						echo __('Time spent working on the issue');
						break;
					case 'milestone':
						echo __('Targetted for milestone');
						break;
					default:
						echo __(ucfirst($item));
						break;
				}

			}

		?>
	</td>
	<td style="padding: 2px; text-align: center;">
		<?php if (in_array($key, array('status'))): ?>
			<input type="hidden" name="field[<?php echo $key; ?>][visible]" value="1"><?php echo image_tag('action_ok.png'); ?>
		<?php else: ?>
			<input type="checkbox" onclick="if (this.checked) { $('f_<?php echo $issuetype->getID(); ?>_<?php echo $key; ?>_reportable').enable(); } else { $('f_<?php echo $issuetype->getID(); ?>_<?php echo $key; ?>_reportable').disable(); }" name="field[<?php echo $key; ?>][visible]" value="1"<?php if (array_key_exists($key, $visiblefields)): ?> checked<?php endif; ?>>
		<?php endif; ?>
	</td>
	<td style="padding: 2px; text-align: center;"><input type="checkbox" onclick="if (this.checked) { $('f_<?php echo $issuetype->getID(); ?>_<?php echo $key; ?>_additional').enable();$('f_<?php echo $issuetype->getID(); ?>_<?php echo $key; ?>_required').enable(); } else { $('f_<?php echo $issuetype->getID(); ?>_<?php echo $key; ?>_additional').disable();$('f_<?php echo $issuetype->getID(); ?>_<?php echo $key; ?>_required').disable(); }" id="f_<?php echo $issuetype->getID(); ?>_<?php echo $key; ?>_reportable" name="field[<?php echo $key; ?>][reportable]" value="1"<?php if (array_key_exists($key, $visiblefields) && $visiblefields[$key]['reportable']): ?> checked<?php endif; ?><?php if (!array_key_exists($key, $visiblefields) && !in_array($key, array('status'))): ?> disabled<?php endif; ?>></td>
	<td style="padding: 2px; text-align: center;">
		<?php if (in_array($key, array('fu'))): ?>
			<input type="hidden" id="f_<?php echo $issuetype->getID(); ?>_<?php echo $key; ?>_additional" name="field[<?php echo $key; ?>][additional]" value="1"><?php echo image_tag('action_ok.png'); ?>
		<?php elseif (!in_array($key, array('description', 'reproduction_steps'))): ?>
			<input type="checkbox" id="f_<?php echo $issuetype->getID(); ?>_<?php echo $key; ?>_additional" name="field[<?php echo $key; ?>][additional]" value="1"<?php if (array_key_exists($key, $visiblefields) && $visiblefields[$key]['additional']): ?> checked<?php endif; ?><?php if ((!array_key_exists($key, $visiblefields) || !$visiblefields[$key]['reportable']) && !in_array($key, array('status'))): ?> disabled<?php endif; ?>>
		<?php else: ?>
			<input type="hidden" id="f_<?php echo $issuetype->getID(); ?>_<?php echo $key; ?>_additional" name="fu"> - 
		<?php endif; ?>
	</td>
	<td style="padding: 2px; text-align: center;"><input type="checkbox" id="f_<?php echo $issuetype->getID(); ?>_<?php echo $key; ?>_required" name="field[<?php echo $key; ?>][required]" value="1"<?php if (array_key_exists($key, $visiblefields) && $visiblefields[$key]['required']): ?> checked<?php endif; ?><?php if ((!array_key_exists($key, $visiblefields) || !$visiblefields[$key]['reportable']) && !in_array($key, array('status'))): ?> disabled<?php endif; ?>></td>
</tr>