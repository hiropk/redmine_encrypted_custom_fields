# frozen_string_literal: true

# Redmine Encrypted Custom Fields
# Copyright (C) 2026 Hiroyuki Kano
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

Redmine::Plugin.register :redmine_encrypted_custom_fields do
  name 'Redmine Encrypted Custom Fields'
  author 'Hiroyuki Kano'
  description 'Adds an "Encrypted text" issue custom field format. Values are stored ' \
              'with AES-256-GCM, masked everywhere, and revealed only on demand with an audit trail.'
  version RedmineEncryptedCustomFields::VERSION
  url 'https://github.com/hiropk/redmine_encrypted_custom_fields'
  requires_redmine version_or_higher: '6.0.0'

  project_module :issue_tracking do
    # require: :loggedin により、匿名ユーザーのロールにはこれらの権限を付与できない。
    permission :view_encrypted_custom_fields, {}, read: true, require: :loggedin
    permission :reveal_encrypted_custom_fields, {encrypted_custom_fields: [:reveal]},
               read: true, require: :loggedin
    permission :edit_encrypted_custom_fields, {}, require: :loggedin
  end

  menu :admin_menu, :encrypted_custom_field_audit_logs,
       {controller: 'encrypted_custom_field_audit_logs', action: 'index'},
       caption: :label_ecf_audit_logs, icon: 'shield-check', html: {class: 'icon'}
end

RedmineEncryptedCustomFields.setup
