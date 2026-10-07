# frozen_string_literal: true

require_relative '../test_helper'

# どの出力経路でもマスク（または何も出さない）でなければならず、
# 平文も保存済みの暗号文も出してはならない。
class EncryptedCustomFieldsLeakTest < Redmine::IntegrationTest
  include EncryptedCustomFieldsTestHelper

  MASK = RedmineEncryptedCustomFields::MASK_TEXT

  def setup
    super
    setup_encryption_key
    @field = create_encrypted_field
    grant(1, *ALL_PERMISSIONS)
    ActionMailer::Base.deliveries.clear
    with_settings(notified_events: %w(issue_added issue_updated)) do
      @issue = issue_with_secret(@field)
    end
    @ciphertext = raw_value(@issue, @field)
  end

  def teardown
    restore_encryption_key
    Setting.rest_api_enabled = '0'
  end

  def assert_no_leak(text, message=nil)
    text = text.to_s.dup.force_encoding(Encoding::BINARY)
    assert_not_includes text, SECRET.b, message
    assert_not_includes text, @ciphertext.b, message
    assert_not_includes text, 'ecf:v1:'.b, message
  end

  def test_issue_list_html_and_csv
    log_user('jsmith', 'jsmith')
    get '/projects/ecookbook/issues', params: {set_filter: 1, c: ['subject', "cf_#{@field.id}"]}
    assert_response :success
    assert_no_leak response.body
    assert_select "td.cf_#{@field.id} .ecf-mask"
    assert_select "td.cf_#{@field.id} .ecf-reveal", 0

    get '/projects/ecookbook/issues.csv', params: {set_filter: 1, c: ['subject', "cf_#{@field.id}"]}
    assert_response :success
    assert_no_leak response.body
    assert_includes response.body, MASK

    get '/projects/ecookbook/issues.csv', params: {set_filter: 1, c: ['all_inline']}
    assert_no_leak response.body
  end

  def test_issue_and_list_pdf
    log_user('jsmith', 'jsmith')
    get "/issues/#{@issue.id}.pdf"
    assert_response :success
    assert_no_leak pdf_text(response.body)

    get '/projects/ecookbook/issues.pdf', params: {set_filter: 1, c: ['subject', "cf_#{@field.id}"]}
    assert_response :success
    assert_no_leak pdf_text(response.body)
  end

  def test_rest_api
    Setting.rest_api_enabled = '1'
    %w(json xml).each do |format|
      get "/issues/#{@issue.id}.#{format}?include=journals", headers: credentials('jsmith')
      assert_response :success
      assert_no_leak response.body, format
      assert_includes response.body, MASK

      get "/issues.#{format}?project_id=1", headers: credentials('jsmith')
      assert_response :success
      assert_no_leak response.body, format
    end

    get "/issues/#{@issue.id}.json", headers: credentials('jsmith')
    field = response.parsed_body['issue']['custom_fields'].detect {|cf| cf['id'] == @field.id}
    assert_equal MASK, field['value']
  end

  def test_rest_api_hides_field_without_view_permission
    Setting.rest_api_enabled = '1'
    get "/issues/#{@issue.id}.json?include=journals", headers: credentials('dlopper', 'foo')
    assert_response :success
    assert_nil response.parsed_body['issue']['custom_fields'].detect {|cf| cf['id'] == @field.id}
    details = response.parsed_body['issue']['journals'].flat_map {|j| j['details']}
    assert_nil details.detect {|d| d['property'] == 'cf' && d['name'] == @field.id.to_s}
  end

  def test_rest_api_update
    Setting.rest_api_enabled = '1'
    put "/issues/#{@issue.id}.json",
        params: {issue: {custom_fields: [{id: @field.id, value: {action: 'replace', encrypted_value: 'via-api'}}]}},
        headers: credentials('jsmith'), as: :json
    assert_response :no_content
    assert_equal 'via-api', RedmineEncryptedCustomFields::Cipher.decrypt(raw_value(@issue, @field), aad: aad(@issue, @field))

    # 受け取ったマスク値をそのまま送り返したクライアントでは、値が維持される。
    stored = raw_value(@issue, @field)
    put "/issues/#{@issue.id}.json", params: {issue: {custom_fields: [{id: @field.id, value: MASK}]}},
                                    headers: credentials('jsmith'), as: :json
    assert_response :no_content
    assert_equal stored, raw_value(@issue, @field)

    # 平文の値は明示的に拒否される。
    put "/issues/#{@issue.id}.json", params: {issue: {custom_fields: [{id: @field.id, value: 'plain'}]}},
                                    headers: credentials('jsmith'), as: :json
    assert_response :unprocessable_content
    assert_equal stored, raw_value(@issue, @field)
  end

  def test_notification_mails
    assert ActionMailer::Base.deliveries.any?
    ActionMailer::Base.deliveries.each do |mail|
      assert_no_leak mail.encoded
    end

    ActionMailer::Base.deliveries.clear
    with_settings(notified_events: %w(issue_added)) do
      issue = Issue.new(project_id: 1, tracker_id: 1, author_id: 2, subject: 'with secret', priority: IssuePriority.first, status_id: 1)
      issue.custom_field_values = {@field.id.to_s => replace_value}
      issue.save!
    end
    assert ActionMailer::Base.deliveries.any?
    ActionMailer::Base.deliveries.each do |mail|
      assert_no_leak mail.encoded
    end
    # jsmith（閲覧権限あり）にはマスクが見え、dlopper（権限なし）には
    # フィールド自体が見えない。
    to_jsmith = ActionMailer::Base.deliveries.detect {|m| m.to.include?('jsmith@somenet.foo')}
    assert_includes to_jsmith.text_part.body.to_s, "API Token: #{MASK}"
    to_dlopper = ActionMailer::Base.deliveries.detect {|m| m.to.include?('dlopper@somenet.foo')}
    assert_not_includes to_dlopper.text_part.body.to_s, 'API Token' if to_dlopper
  end

  def test_journal_history_atom_and_activity
    log_user('jsmith', 'jsmith')
    get "/issues/#{@issue.id}"
    assert_no_leak response.body
    assert_select '#history ul.journal-details li', text: /API Token/

    get "/issues/#{@issue.id}.atom"
    assert_response :success
    assert_no_leak response.body

    get '/projects/ecookbook/activity', params: {show_issues: 1}
    assert_no_leak response.body

    get '/issues/changes.atom', params: {project_id: 'ecookbook'}
    assert_response :success
    assert_no_leak response.body
  end

  def test_search_does_not_find_values
    log_user('jsmith', 'jsmith')
    get '/search', params: {q: SECRET, issues: 1}
    assert_response :success
    assert_select '#search-results dt', 0
  end

  def test_filter_on_encrypted_field_is_ignored
    log_user('jsmith', 'jsmith')
    get '/projects/ecookbook/issues', params: {set_filter: 1, f: ["cf_#{@field.id}"], op: {"cf_#{@field.id}" => '~'}, v: {"cf_#{@field.id}" => ['S3cr']}}
    assert_response :success
    assert_select "#filters-table tr#tr_cf_#{@field.id}", 0
  end

  # ブロック内のログ出力（DEBUG 以上）を文字列で返す。
  def capture_log
    log = StringIO.new
    logger = ActiveSupport::Logger.new(log)
    logger.level = Logger::DEBUG
    saved = [Rails.logger, ActionController::Base.logger, ActiveRecord::Base.logger]
    Rails.logger = ActionController::Base.logger = ActiveRecord::Base.logger = logger
    begin
      yield
    ensure
      Rails.logger, ActionController::Base.logger, ActiveRecord::Base.logger = saved
    end
    log.string
  end

  def test_form_update_and_parameter_log
    output = capture_log do
      log_user('jsmith', 'jsmith')
      patch "/issues/#{@issue.id}", params: {issue: {custom_field_values: {@field.id.to_s => {action: 'replace', encrypted_value: "#{SECRET}-2"}}}}
      assert_response :redirect
      get "/issues/#{@issue.id}"
    end

    assert_match /"encrypted_value"\s*=>\s*"\[FILTERED\]"/, output
    assert_not_includes output, SECRET
    assert_equal "#{SECRET}-2", RedmineEncryptedCustomFields::Cipher.decrypt(raw_value(@issue, @field), aad: aad(@issue, @field))
  end

  # 決められた形式以外（平文の文字列）で送られた値も、拒否される前のログで伏せられる。
  # 通常のカスタムフィールドの値はこれまでどおりログに出る。
  def test_plain_values_are_filtered_from_request_log
    plain = IssueCustomField.create!(name: 'Plain', field_format: 'string', is_for_all: true, visible: true, tracker_ids: [1])
    Setting.rest_api_enabled = '1'
    output = capture_log do
      log_user('jsmith', 'jsmith')
      patch "/issues/#{@issue.id}", params: {issue: {custom_field_values: {@field.id.to_s => "#{SECRET}-form", plain.id.to_s => 'visible-normal-value'}}}
      assert_response :success # バリデーションエラーでフォームを再表示

      put "/issues/#{@issue.id}.json",
          params: {issue: {custom_fields: [{id: @field.id, value: "#{SECRET}-api"}, {id: plain.id, value: 'visible-api-value'}]}},
          headers: credentials('jsmith'), as: :json
      assert_response :unprocessable_content

      put "/issues/#{@issue.id}.xml",
          params: %(<issue><custom_fields type="array"><custom_field id="#{@field.id}"><value>#{SECRET}-xml</value></custom_field></custom_fields></issue>),
          headers: credentials('jsmith').merge('CONTENT_TYPE' => 'application/xml')
      assert_response :unprocessable_content
    end

    assert_not_includes output, SECRET
    assert_includes output, 'visible-normal-value'
    assert_includes output, 'visible-api-value'
    assert_equal @ciphertext, raw_value(@issue, @field)
  end

  def test_validation_error_does_not_echo_value
    @field.update!(regexp: '\A[a-z]+\z')
    log_user('jsmith', 'jsmith')
    patch "/issues/#{@issue.id}", params: {issue: {custom_field_values: {@field.id.to_s => {action: 'replace', encrypted_value: SECRET}}}}
    assert_response :success
    assert_select '#errorExplanation'
    assert_no_leak response.body
    assert_select "input[name='issue[custom_field_values][#{@field.id}][action]'][value=replace][checked]"
  end

  def test_bulk_update_cannot_set_encrypted_values
    log_user('jsmith', 'jsmith')
    stored = raw_value(@issue, @field)
    post '/issues/bulk_update', params: {ids: [@issue.id, 2], issue: {custom_field_values: {@field.id.to_s => {action: 'replace', encrypted_value: 'bulk'}}}}
    assert_response :redirect
    assert_equal stored, raw_value(@issue, @field)
    assert_nil raw_value(Issue.find(2), @field)

    # custom_fields[] 形式でも除外される（削除も置換もできない）
    post '/issues/bulk_update', params: {ids: [@issue.id, 2], issue: {custom_fields: [{id: @field.id, value: {action: 'clear'}}]}}
    assert_response :redirect
    assert_equal stored, raw_value(@issue, @field)
    post '/issues/bulk_update', params: {ids: [@issue.id, 2], issue: {custom_fields: [{id: @field.id, value: {action: 'replace', encrypted_value: 'bulk'}}]}}
    assert_response :redirect
    assert_equal stored, raw_value(@issue, @field)
    assert_nil raw_value(Issue.find(2), @field)
  end

  # 本体の一括更新（ほかの項目）は引き続き動く
  def test_bulk_update_of_other_attributes_still_works
    log_user('jsmith', 'jsmith')
    post '/issues/bulk_update', params: {ids: [@issue.id, 2], issue: {priority_id: 6, custom_field_values: {@field.id.to_s => {action: 'clear'}}}}
    assert_response :redirect
    assert_equal [6, 6], Issue.where(id: [@issue.id, 2]).order(:id).pluck(:priority_id)
    assert_equal @ciphertext, raw_value(@issue, @field)
  end

  def test_copy_through_controller_drops_secret
    log_user('jsmith', 'jsmith')
    get "/projects/ecookbook/issues/#{@issue.id}/copy"
    assert_response :success
    assert_no_leak response.body
    post '/projects/ecookbook/issues', params: {copy_from: @issue.id, issue: {project_id: 1, tracker_id: 1, subject: 'copied', status_id: 1, priority_id: 4}}
    copy = Issue.order(:id).last
    assert_equal 'copied', copy.subject
    assert raw_value(copy, @field).blank?
  end
end
