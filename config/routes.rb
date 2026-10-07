# frozen_string_literal: true

# POST のみで、format の指定は受け付けない（GET や ?format=json は拒否する）。
post 'issues/:issue_id/encrypted_custom_fields/:custom_field_id/reveal',
     to: 'encrypted_custom_fields#reveal',
     as: 'reveal_issue_encrypted_custom_field',
     format: false,
     constraints: {issue_id: /\d+/, custom_field_id: /\d+/}

get 'admin/encrypted_custom_field_audit_logs',
    to: 'encrypted_custom_field_audit_logs#index',
    as: 'encrypted_custom_field_audit_logs'
