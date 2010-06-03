<?php TBGContext::loadLibrary('publish/publish'); ?>
<table style="margin-top: 0px; table-layout: fixed; width: 100%" cellpadding=0 cellspacing=0>
	<tr>
		<td class="left_bar" style="width: 250px;">
			<?php include_component('leftmenu', array('article' => $article)); ?>
		</td>
		<td class="main_area article">
			<a name="top"></a>
			<div class="article" style="width: auto; padding: 5px; position: relative;">
				<div class="header">
					<?php echo link_tag(make_url('publish_article', array('article_name' => $article->getName())), __('Show article'), array('style' => 'float: right;')); ?>
					<?php echo link_tag(make_url('publish_article_edit', array('article_name' => $article->getName())), __('Edit'), array('style' => 'float: right; margin-right: 15px;')); ?>
					<?php if (TBGContext::isProjectContext()): ?>
						<?php if ((strpos($article->getName(), ucfirst(TBGContext::getCurrentProject()->getKey())) == 0) || ($article->isCategory() && strpos($article->getName(), ucfirst(TBGContext::getCurrentProject()->getKey())) == 9)): ?>
							<?php $project_article_name = substr($article->getName(), ($article->isCategory() * 9) + strlen(TBGContext::getCurrentProject()->getKey())+1); ?>
							<?php if ($article->isCategory()): ?><span class="faded_blue">Category:</span><?php endif; ?><span class="faded_dark"><?php echo ucfirst(TBGContext::getCurrentProject()->getKey()); ?>:</span><?php echo get_spaced_name($project_article_name); ?>
						<?php endif; ?>
					<?php elseif (substr($article->getName(), 0, 9) == 'Category:'): ?>
						<span class="faded_blue">Category:</span><?php echo get_spaced_name(substr($article->getName(), 9)); ?>
					<?php else: ?>
						<?php echo get_spaced_name($article->getName()); ?>
					<?php endif; ?>
					<span class="faded_medium"><?php echo __('%article_name% ~ History', array('%article_name%' => '')); ?></span>
				</div>
			</div>
			<?php if ($history_action == 'list'): ?>
				<form action="<?php echo make_url('publish_article_diff', array('article_name' => $article->getName())); ?>" method="post">
					<table cellpadding="0" cellspacing="0" id="article_history">
						<thead>
							<tr>
								<th style="width: 25px; text-align: center;">#</th>
								<th style="width: 150px;"><?php echo __('Updated'); ?></th>
								<th style="width: 200px;"><?php echo __('Author'); ?></th>
								<th><?php echo __('Comment'); ?></th>
								<th style="width: 60px;" colspan="2"><?php echo __('Compare'); ?></th>
								<th style="width: 150px;"><?php echo __('Actions'); ?></th>
							</tr>
						</thead>
						<tbody>
							<?php foreach ($history as $revision => $history_item): ?>
								<tr>
									<td style="text-align: center;"><b><?php echo $revision; ?></b></td>
									<td style="text-align: center;"><?php echo tbg_formatTime($history_item['updated'], 20); ?></td>
									<td><i><?php echo ($history_item['author'] instanceof TBGUser) ? $history_item['author']->getName() : ''; ?></i></td>
									<td><?php echo $history_item['change_reason']; ?></td>
									<td style="width: 30px; text-align: center;">
										<?php if ($revision > 1): ?>
											<input type="radio" value="<?php echo $revision; ?>" <?php if ($revision == $revision_count): ?>checked <?php endif; ?> name="from_revision" id="from_revision_<?php echo $revision; ?>">
										<?php endif; ?>
									</td>
									<td style="width: 30px; text-align: center;">
										<?php if ($revision < $revision_count): ?>
											<input type="radio" value="<?php echo $revision; ?>" <?php if ($revision == $revision_count - 1): ?>checked <?php endif; ?> name="to_revision" id="to_revision_<?php echo $revision; ?>">
										<?php endif; ?>
									</td>
									<td>
										<?php if ($revision_count > 1): ?>
											<a href="#"><?php echo __('Restore this version'); ?></a>
										<?php endif; ?>
									</td>
								</tr>
							<?php endforeach; ?>
						</tbody>
						<tfoot>
							<tr>
								<td colspan="4">&nbsp;</td>
								<td colspan="2" style="text-align: center;"><input type="submit" value="<?php echo __('Compare'); ?>"></td>
								<td>&nbsp;</td>
							</tr>
						</tfoot>
					</table>
				</form>
			<?php elseif ($history_action == 'diff'): ?>
				<p style="padding: 0 5px 10px 10px; font-size: 13px;">
					<?php echo '<b>'.__('Showing the difference between revisions: %from_revision% &rArr; %to_revision%', array('&rArr;' => '<b>&rArr;</b>', '%from_revision%' => '</b><i>'.__('%revision_number%, by %author% [%date%]', array('%revision_number%' => $from_revision, '%author%' => $from_revision_author, '%date%' => tbg_formatTime($from_revision_date, 20))).'</i>', '%to_revision%' => '<i>'.__('%revision_number%, by %author% [%date%]', array('%revision_number%' => $to_revision, '%author%' => $to_revision_author, '%date%' => tbg_formatTime($to_revision_date, 20))).'</i>')); ?><br />
					<?php echo link_tag(make_url('publish_article_history', array('article_name' => $article->getName())), '&lt;&lt; '.__('Back to history')); ?>
				</p>
				<?php $cc = 1; ?>
				<table cellpadding="0" cellspacing="0" id="article_diff">
					<?php $odd = true; ?>
					<?php foreach ($diff as $line): ?>
						<tr<?php if ($odd): ?> class="odd"<?php endif; ?>>
							<td style="width: 40px; text-align: right; font-weight: bold; padding-right: 5px;"><?php echo $cc; ?>.</td>
							<td style="padding: 0;"><?php echo $line; ?></td>
						</tr>
						<?php $cc++; ?>
						<?php $odd = !$odd; ?>
					<?php endforeach; ?>
				</table>
			<?php endif; ?>
		</td>
	</tr>
</table>