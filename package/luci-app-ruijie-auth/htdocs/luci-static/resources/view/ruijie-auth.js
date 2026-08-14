'use strict';
'require view';
'require form';
'require uci';
'require fs';

var STATUS_FILE = '/var/run/ruijie-auth.status';

function status_text(content) {
	if (content && String(content).trim() !== '') {
		var t = parseInt(String(content).trim(), 10);
		if (!isNaN(t) && t > 0)
			return _('Authenticated (since %s)').format(new Date(t * 1000).toLocaleString());
		return _('Authenticated');
	}
	return _('Not authenticated');
}

return view.extend({
	load: function() {
		return Promise.all([
			uci.load('ruijie'),
			fs.read(STATUS_FILE).catch(function() { return null; })
		]);
	},

	render: function(data) {
		var m, s, o;

		m = new form.Map('ruijie', _('Ruijie 802.1X Client'),
			_('EAP-MD5 authentication client for Ruijie campus networks. '
			  + 'The daemon runs as init service ruijie-auth.'));

		s = m.section(form.NamedSection, 'main', 'ruijie', _('Authentication'));
		s.anonymous = true;

		o = s.option(form.Flag, 'enabled', _('Enable'));
		o.default = '0';
		o.rmempty = false;

		o = s.option(form.Value, 'interface', _('Uplink interface'),
			_('Interface facing the switch (EAPOL frames are sent here).'));
		o.default = 'wan';
		o.rmempty = false;

		o = s.option(form.Value, 'username', _('Username'));
		o.rmempty = false;

		o = s.option(form.Value, 'password', _('Password'));
		o.password = true;

		o = s.option(form.Value, 'auth_servers', _('Auth servers'),
			_('Semicolon separated IP list, max 27 bytes total.'));
		o.default = '202.199.30.31;202.199.29.94';
		o.rmempty = false;

		o = s.option(form.Value, 'mac', _('Source MAC (optional)'),
			_('Leave empty to auto-detect; some campuses bind the device MAC.'));
		o.placeholder = _('auto detect');

		o = s.option(form.Value, 'timeout', _('Receive timeout (s)'));
		o.default = '3';
		o.datatype = 'ufloat';

		o = s.option(form.Value, 'retry_delay', _('Retry delay (s)'));
		o.default = '3';
		o.datatype = 'ufloat';

		o = s.option(form.Value, 'start_burst', _('EAPOL-Start burst'));
		o.default = '2';
		o.datatype = 'uinteger';

		o = s.option(form.Flag, 'debug', _('Debug logging (hex dumps)'));
		o.default = '0';

		o = s.option(form.DummyValue, '_status', _('Current status'));
		o.textvalue = status_text(data[1]);

		// 保存 UCI 后重启服务
		var save = m.save;
		m.save = function() {
			return save.apply(m, arguments).then(function(res) {
				return fs.exec('/etc/init.d/ruijie-auth', ['restart'])
					.catch(function() { return res; });
			});
		};

		return m.render();
	}
});
