# frozen_string_literal: true

class CreateEncryptedCustomFieldAuditLogs < ActiveRecord::Migration[7.2]
  def change
    create_table :encrypted_custom_field_audit_logs do |t|
      t.string :action, limit: 30, null: false
      t.integer :user_id, null: false
      t.integer :project_id
      t.integer :issue_id, null: false
      t.integer :custom_field_id, null: false
      t.string :ip_address, limit: 45
      t.string :user_agent, limit: 255
      t.string :request_id, limit: 64
      t.datetime :created_on, null: false
    end
    add_index :encrypted_custom_field_audit_logs, :created_on
    add_index :encrypted_custom_field_audit_logs, :issue_id
    add_index :encrypted_custom_field_audit_logs, :user_id
  end
end
