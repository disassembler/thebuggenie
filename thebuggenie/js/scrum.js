function addUserStory(url)
{
	var params = Form.serialize('add_user_story_form');
	new Ajax.Request(url, {
	asynchronous:true,
	method: "post",
	evalScripts: true,
	parameters: params,
	onLoading: function (transport) {
		$('user_story_add_indicator').show();
	},
	onSuccess: function (transport) {
		var json = transport.responseJSON;
		if (json.failed)
		{
			failedMessage(json.error);
			$('user_story_add_indicator').hide();
			$('message_failed').show();
		}
		else
		{
			Form.reset('add_user_story_form');
			$('message_failed').hide();
			$('user_story_add_indicator').hide();
			$('message_user_story_added').show();
			$('scrum_sprint_0_list').insert({bottom: json.content});
			$('scrum_no_unassigned').hide();
			new Draggable('scrum_story_' + json.story_id, { revert: true });
			new Effect.Fade('message_user_story_added', {delay: 20} );
		}
	},
	onFailure: function (transport) {
		$('user_story_add_indicator').hide();
	},
	insertion: Insertion.Bottom
	});
}

function addSprint(url, assign_url)
{
	var params = Form.serialize('add_sprint_form');
	new Ajax.Request(url, {
	asynchronous:true,
	method: "post",
	evalScripts: true,
	parameters: params,
	onLoading: function (transport) {
		$('sprint_add_indicator').show();
	},
	onSuccess: function (transport) {
		var json = transport.responseJSON;
		if (json.failed)
		{
			failedMessage(json.error);
			$('sprint_add_indicator').hide();
			$('message_failed').show();
		}
		else
		{
			Form.reset('add_sprint_form');
			$('message_failed').hide();
			$('sprint_add_indicator').hide();
			$('message_sprint_added').show();
			$('scrum_sprints').insert({bottom: json.content});
			Droppables.add('scrum_sprint_' + json.sprint_id, { hoverclass: 'highlighted', onDrop: function (dragged, dropped, event) { assignStory(assign_url, dragged, dropped)}});
		}
	},
	onFailure: function (transport) {
		$('user_story_add_indicator').hide();
	},
	insertion: Insertion.Bottom
	});
}

function assignStory(url, dragged, dropped)
{
	new Ajax.Request(url, {
	asynchronous:true,
	method: "post",
	evalScripts: true,
	parameters: { story_id: $(dragged.id + '_id').getValue(), sprint_id: $(dropped.id + '_id').getValue() },
	onLoading: function (transport) {
		$(dropped.id + '_indicator').show();
	},
	onSuccess: function (transport) {
		var json = transport.responseJSON;
		if (json.failed)
		{
			failedMessage(json.error);
			$(dropped.id + '_indicator').hide();
			$('message_failed').show();
		}
		else
		{
			$('message_failed').hide();
			$(dropped.id + '_indicator').hide();
			$(dropped.id + '_list').insert(Element.remove(dragged), { insertion: Insertion.Bottom, queue: 'end' });
			$('scrum_sprint_' + json.old_sprint_id + '_issues').update(json.old_issues);
			$('scrum_sprint_' + json.new_sprint_id + '_issues').update(json.new_issues);
			$('scrum_sprint_' + json.old_sprint_id + '_estimated_points').update(json.old_estimated_points);
			$('scrum_sprint_' + json.new_sprint_id + '_estimated_points').update(json.new_estimated_points);
			($('scrum_sprint_0_list').childElements().size() == 0) ? $('scrum_no_unassigned').show() : $('scrum_no_unassigned').hide();
			$('message_user_story_assigned').show();
			new Effect.Fade('message_user_story_assigned', {delay: 20} );
		}
	},
	onFailure: function (transport) {
		$(dropped.id + '_indicator').hide();
	}
	});
}

function setStoryColor(url, story_id, color)
{
	new Ajax.Request(url, {
	asynchronous:true,
	method: "post",
	parameters: { color: color },
	onLoading: function (transport) {
		$('color_selector_' + story_id + '_indicator').show();
	},
	onSuccess: function (transport) {
		var json = transport.responseJSON;
		if (json.failed)
		{
			failedMessage(json.error);
			$('color_selector_' + story_id + '_indicator').hide();
			$('color_selector_' + story_id).hide();
			$('message_failed').show();
		}
		else
		{
			$('message_failed').hide();
			$('color_selector_' + story_id + '_indicator').hide();
			$('color_selector_' + story_id).hide();
			$('story_color_' + story_id).style.backgroundColor = color;
		}
	},
	onFailure: function (transport) {
		$('color_selector_' + story_id + '_indicator').hide();
		$('color_selector_' + story_id).hide();
	}
	});
}

function setStoryEstimatedPoints(url, story_id)
{
	points = $('scrum_story_' + story_id + '_points_input').getValue();
	new Ajax.Request(url, {
	asynchronous:true,
	method: "post",
	parameters: { estimated_points: points },
	onLoading: function (transport) {
		$('point_selector_' + story_id + '_indicator').show();
	},
	onSuccess: function (transport) {
		var json = transport.responseJSON;
		if (json.failed)
		{
			failedMessage(json.error);
			$('point_selector_' + story_id + '_indicator').hide();
			$('scrum_story_' + story_id + '_estimation').hide();
			$('message_failed').show();
		}
		else
		{
			$('message_failed').hide();
			$('point_selector_' + story_id + '_indicator').hide();
			$('scrum_story_' + story_id + '_estimation').hide();
			$('scrum_story_' + story_id + '_points').update(json.points);
			$('scrum_sprint_' + json.sprint_id + '_estimated_points').update(json.new_estimated_points);
		}
	},
	onFailure: function (transport) {
		$('point_selector_' + story_id + '_indicator').hide();
		$('scrum_story_' + story_id + '_estimation').hide();
	}
	});
}