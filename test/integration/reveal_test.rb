# frozen_string_literal: true

require_relative '../test_helper'

class EncryptedCustomFieldsRevealTest < Redmine::IntegrationTest
  include EncryptedCustomFieldsTestHelper

  def setup
    super
    setup_encryption_key
    @field = create_encrypted_field
    grant(1, *ALL_PERMISSIONS) # 管理者ロール（jsmith）
    @issue = issue_with_secret(@field)
  end

  def teardown
    restore_encryption_key
    ActionController::Base.allow_forgery_protection = false
    Setting.rest_api_enabled = '0'
  end

  def reveal_path(issue=@issue, field=@field)
    "/issues/#{issue.id}/encrypted_custom_fields/#{field.id}/reveal"
  end

  def assert_no_secret
    assert_not_includes response.body, SECRET
  end

  def test_reveal_returns_plaintext_and_writes_audit_log
    log_user('jsmith', 'jsmith')
    assert_difference 'EncryptedCustomFieldAuditLog.count', 1 do
      post reveal_path
    end
    assert_response :success
    assert_equal SECRET, response.parsed_body['value']
    assert_includes response.headers['Cache-Control'], 'no-store'

    log = EncryptedCustomFieldAuditLog.last
    assert_equal ['reveal', 2, 1, @issue.id, @field.id], [log.action, log.user_id, log.project_id, log.issue_id, log.custom_field_id]
    assert log.ip_address.present?
    assert_not_includes log.attributes.values.join, SECRET
    assert_not_includes log.attributes.values.join, raw_value(@issue, @field)
  end

  def test_issue_page_contains_mask_and_button_but_no_secret
    log_user('jsmith', 'jsmith')
    get "/issues/#{@issue.id}"
    assert_response :success
    assert_no_secret
    assert_not_includes response.body, raw_value(@issue, @field)
    assert_select ".ecf-field[data-ecf-reveal-url='#{reveal_path}'] .ecf-mask", text: RedmineEncryptedCustomFields::MASK_HTML
    assert_select '.ecf-field .ecf-reveal'
    # 編集フォームには平文も暗号文も埋め込まれない。
    assert_select "input[name='issue[custom_field_values][#{@field.id}][encrypted_value]'][type=password]:not([value])"
    assert_select "input[name='issue[custom_field_values][#{@field.id}][action]'][value=keep][checked]"
  end

  def test_no_reveal_button_without_reveal_permission
    grant(2, :view_encrypted_custom_fields)
    log_user('dlopper', 'foo')
    get "/issues/#{@issue.id}"
    assert_select '.ecf-field .ecf-mask'
    assert_select '.ecf-reveal', 0
  end

  def test_reveal_without_reveal_permission_is_forbidden
    grant(2, :view_encrypted_custom_fields)
    log_user('dlopper', 'foo')
    assert_no_difference 'EncryptedCustomFieldAuditLog.count' do
      post reveal_path
    end
    assert_response :forbidden
    assert_no_secret
  end

  def test_reveal_without_view_permission_is_not_found
    grant(2, :reveal_encrypted_custom_fields)
    log_user('dlopper', 'foo')
    post reveal_path
    assert_response :not_found
    assert_no_secret
  end

  def test_reveal_on_invisible_issue_is_not_found
    # チケット #4 は非公開のプロジェクト 2 に属し、dlopper はそのメンバーではない。
    hidden = Issue.find(4)
    assert_not hidden.visible?(User.find(3))
    issue_with_secret(@field, issue_id: 4)
    grant(2, *ALL_PERMISSIONS)
    log_user('dlopper', 'foo')
    post reveal_path(hidden)
    assert_response :not_found
    assert_no_secret
  end

  def test_reveal_with_other_project_role_only_is_forbidden
    # jsmith はプロジェクト 1 では管理者（復号権限あり）だが、プロジェクト 2 では開発者。
    # プロジェクト 2 の値の復号は拒否されなければならない。
    issue = issue_with_secret(@field, issue_id: 4)
    assert issue.visible?(User.find(2))
    revoke(2, :reveal_encrypted_custom_fields)
    grant(2, :view_encrypted_custom_fields)
    log_user('jsmith', 'jsmith')
    post reveal_path(issue)
    assert_response :forbidden
    assert_no_secret
  end

  def test_reveal_of_field_not_enabled_for_issue_is_not_found
    @field.update!(is_for_all: false, project_ids: [2])
    log_user('jsmith', 'jsmith')
    post reveal_path
    assert_response :not_found
    assert_no_secret
  end

  def test_reveal_of_non_encrypted_field_is_not_found
    log_user('jsmith', 'jsmith')
    post reveal_path(@issue, CustomField.find(2))
    assert_response :not_found
  end

  def test_anonymous_is_refused
    post reveal_path
    assert_response :forbidden
    assert_no_secret
  end

  def test_get_is_not_routed
    log_user('jsmith', 'jsmith')
    get reveal_path
    assert_response :not_found
    assert_no_secret
  end

  def test_missing_csrf_token_is_refused
    log_user('jsmith', 'jsmith')
    ActionController::Base.allow_forgery_protection = true
    assert_no_difference 'EncryptedCustomFieldAuditLog.count' do
      post reveal_path
    end
    assert_response 422
    assert_no_secret
  end

  def test_valid_csrf_token_is_accepted
    log_user('jsmith', 'jsmith')
    ActionController::Base.allow_forgery_protection = true
    get "/issues/#{@issue.id}"
    token = css_select('meta[name=csrf-token]').first['content']
    post reveal_path, headers: {'X-CSRF-Token' => token}
    assert_response :success
    assert_equal SECRET, response.parsed_body['value']
  end

  def test_format_param_cannot_bypass_csrf
    log_user('jsmith', 'jsmith')
    ActionController::Base.allow_forgery_protection = true
    post "#{reveal_path}?format=json"
    assert_not_equal 200, response.status
    assert_no_secret
  end

  def test_api_key_is_refused
    Setting.rest_api_enabled = '1'
    key = User.find(2).api_key
    post reveal_path, headers: {'X-Redmine-API-Key' => key}
    assert_response :forbidden
    post "#{reveal_path}?key=#{key}"
    assert_response :forbidden
    post reveal_path, headers: credentials('jsmith')
    assert_response :forbidden
    assert_no_secret
  end

  def test_api_key_is_refused_even_with_a_session
    Setting.rest_api_enabled = '1'
    log_user('jsmith', 'jsmith')
    post reveal_path, headers: {'X-Redmine-API-Key' => User.find(2).api_key}
    assert_response :forbidden
    assert_no_secret
  end

  def test_value_is_not_returned_when_audit_log_fails
    EncryptedCustomFieldAuditLog.stubs(:create!).raises(ActiveRecord::StatementInvalid, 'disk full')
    log_user('jsmith', 'jsmith')
    post reveal_path
    assert_response :service_unavailable
    assert_no_secret
    assert_nil response.parsed_body['value']
  end

  def test_tampered_value_is_not_returned
    CustomValue.where(customized_id: @issue.id, custom_field_id: @field.id)
               .update_all(value: raw_value(issue_with_secret(@field, issue_id: 2), @field))
    log_user('jsmith', 'jsmith')
    post reveal_path
    assert_response 422
    assert_no_secret
    assert_equal 'reveal_failed', EncryptedCustomFieldAuditLog.last.action
  end

  def test_reveal_with_missing_key_fails_closed
    log_user('jsmith', 'jsmith')
    with_env(KEY_ENV => nil) do
      post reveal_path
    end
    assert_response 422
    assert_no_secret
  end

  def test_audit_log_page_is_admin_only
    log_user('jsmith', 'jsmith')
    post reveal_path
    get '/admin/encrypted_custom_field_audit_logs'
    assert_response :forbidden

    reset!
    log_user('admin', 'admin')
    get '/admin/encrypted_custom_field_audit_logs'
    assert_response :success
    assert_select 'table.ecf-audit-logs tbody tr', 1
    assert_no_secret
  end

  # 画面に「Translation missing」が出ないこと（en / ja）
  def test_pages_have_no_missing_translations
    post reveal_path_as_jsmith
    reset!
    log_user('admin', 'admin')
    %w(en ja).each do |language|
      User.find(1).update!(language: language)
      [
        '/admin/encrypted_custom_field_audit_logs',
        "/issues/#{@issue.id}",
        "/custom_fields/#{@field.id}/edit",
        '/custom_fields/new?type=IssueCustomField&custom_field[field_format]=encrypted_text',
        '/roles/1/edit'
      ].each do |path|
        get path
        assert_response :success, path
        assert_not_includes response.body, 'Translation missing', "#{language} #{path}"
        assert_not_includes response.body, 'translation_missing', "#{language} #{path}"
      end
    end
  end

  private

  def reveal_path_as_jsmith
    log_user('jsmith', 'jsmith')
    reveal_path
  end
end
