# frozen_string_literal: true

require File.expand_path('../../../test/test_helper', __dir__)

module EncryptedCustomFieldsTestHelper
  # 保存データ・レスポンス・メール・ログのどこにも現れてはならない、目印になる値。
  SECRET = 'S3cr3t-CANARY-7f3a9c'
  TEST_KEY = Base64.strict_encode64("0123456789abcdef0123456789abcdef")
  OTHER_KEY = Base64.strict_encode64("fedcba9876543210fedcba9876543210")
  KEY_ENV = RedmineEncryptedCustomFields::EnvironmentKeyProvider::KEY_ENV
  KEY_ID_ENV = RedmineEncryptedCustomFields::EnvironmentKeyProvider::KEY_ID_ENV
  ALL_PERMISSIONS = [:view_encrypted_custom_fields, :reveal_encrypted_custom_fields, :edit_encrypted_custom_fields].freeze

  def setup_encryption_key
    @saved_key_env = ENV.to_h.slice(KEY_ENV, KEY_ID_ENV)
    ENV[KEY_ENV] = TEST_KEY
    ENV.delete(KEY_ID_ENV)
  end

  def restore_encryption_key
    [KEY_ENV, KEY_ID_ENV].each do |name|
      @saved_key_env.key?(name) ? ENV[name] = @saved_key_env[name] : ENV.delete(name)
    end
  end

  def with_env(values)
    saved = values.keys.index_with {|k| ENV[k]}
    values.each {|k, v| v.nil? ? ENV.delete(k) : ENV[k] = v}
    yield
  ensure
    saved.each {|k, v| v.nil? ? ENV.delete(k) : ENV[k] = v}
  end

  # 全ロールに表示し、全プロジェクト・全トラッカーで有効なフィールドを作る。
  def create_encrypted_field(attributes={})
    IssueCustomField.create!(
      {
        name: 'API Token',
        field_format: 'encrypted_text',
        is_for_all: true,
        visible: true,
        tracker_ids: Tracker.pluck(:id)
      }.merge(attributes)
    )
  end

  def grant(role_id, *permissions)
    role = Role.find(role_id)
    permissions.each {|p| role.add_permission!(p)}
    role
  end

  def revoke(role_id, *permissions)
    role = Role.find(role_id)
    permissions.each {|p| role.remove_permission!(p)}
    role
  end

  def replace_value(secret=SECRET)
    {'action' => 'replace', 'encrypted_value' => secret}
  end

  def raw_value(issue, field)
    CustomValue.where(customized_type: 'Issue', customized_id: issue.id, custom_field_id: field.id).pick(:value)
  end

  def aad(issue, field)
    RedmineEncryptedCustomFields::Cipher.aad_for('Issue', issue.id, field.id)
  end

  # field に SECRET を保存したチケットを返す（既定はチケット #1、プロジェクト 1・トラッカー 1）。
  def issue_with_secret(field, issue_id: 1)
    issue = Issue.find(issue_id)
    issue.init_journal(User.find(1))
    issue.custom_field_values = {field.id.to_s => replace_value}
    issue.save!
    Issue.find(issue_id)
  end

  # PDF のストリームを展開し、テキストを検索できるようにする。
  def pdf_text(pdf)
    text = pdf.dup.force_encoding(Encoding::BINARY)
    pdf.b.scan(/stream\r?\n(.*?)\r?\nendstream/m).each do |(stream)|
      text << Zlib::Inflate.inflate(stream)
    rescue Zlib::Error
      next
    end
    text
  end
end
