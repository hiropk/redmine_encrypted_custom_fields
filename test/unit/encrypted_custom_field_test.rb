# frozen_string_literal: true

require_relative '../test_helper'

class EncryptedCustomFieldTest < ActiveSupport::TestCase
  include EncryptedCustomFieldsTestHelper

  Cipher = RedmineEncryptedCustomFields::Cipher

  def setup
    setup_encryption_key
    User.current = nil
    @field = create_encrypted_field
    grant(1, *ALL_PERMISSIONS)
  end

  def teardown
    restore_encryption_key
    User.current = nil
  end

  # -- 保存 ------------------------------------------------------

  def test_only_ciphertext_is_stored
    issue = issue_with_secret(@field)
    stored = raw_value(issue, @field)

    assert Cipher.stored_format?(stored)
    assert_equal SECRET, Cipher.decrypt(stored, aad: aad(issue, @field))
    assert_not CustomValue.where("value LIKE ?", "%#{SECRET}%").exists?
  end

  def test_new_issue_is_encrypted_with_its_own_id
    issue = Issue.new(project_id: 1, tracker_id: 1, author_id: 2, subject: 'new', priority: IssuePriority.first, status_id: 1)
    issue.custom_field_values = {@field.id.to_s => replace_value}
    assert issue.save, issue.errors.full_messages.inspect

    assert_equal SECRET, Cipher.decrypt(raw_value(issue, @field), aad: aad(issue, @field))
  end

  def test_model_read_does_not_decrypt
    issue = issue_with_secret(@field)
    assert_equal raw_value(issue, @field), issue.custom_field_value(@field)
    assert_equal raw_value(issue, @field), issue.custom_value_for(@field).value
  end

  def test_unchanged_save_does_not_reencrypt
    issue = issue_with_secret(@field)
    stored = raw_value(issue, @field)

    issue.init_journal(User.find(1))
    issue.subject = 'changed subject'
    issue.save!
    assert_equal stored, raw_value(issue, @field)

    issue.reload.init_journal(User.find(1))
    issue.custom_field_values = {@field.id.to_s => {'action' => 'keep', 'encrypted_value' => 'ignored'}}
    issue.save!
    assert_equal stored, raw_value(issue, @field)
  end

  def test_blank_submission_keeps_value
    issue = issue_with_secret(@field)
    stored = raw_value(issue, @field)

    ['', nil, {'encrypted_value' => ''}, RedmineEncryptedCustomFields::MASK_TEXT].each do |input|
      issue.reload.init_journal(User.find(1))
      issue.custom_field_values = {@field.id.to_s => input}
      assert issue.save, "#{input.inspect}: #{issue.errors.full_messages.inspect}"
      assert_equal stored, raw_value(issue, @field), input.inspect
    end
  end

  def test_replace
    issue = issue_with_secret(@field)
    stored = raw_value(issue, @field)

    issue.init_journal(User.find(1))
    issue.custom_field_values = {@field.id.to_s => replace_value('new-value')}
    issue.save!

    assert_not_equal stored, raw_value(issue, @field)
    assert_equal 'new-value', Cipher.decrypt(raw_value(issue, @field), aad: aad(issue, @field))
  end

  def test_replace_with_blank_is_an_error
    issue = issue_with_secret(@field)
    issue.custom_field_values = {@field.id.to_s => {'action' => 'replace', 'encrypted_value' => ''}}
    assert_not issue.save
    assert_includes issue.errors.full_messages.join, 'empty value'
  end

  def test_clear
    issue = issue_with_secret(@field)
    issue.init_journal(User.find(1))
    issue.custom_field_values = {@field.id.to_s => {'action' => 'clear'}}
    issue.save!
    assert_equal '', raw_value(issue, @field)
  end

  def test_required_field_cannot_be_cleared
    @field.update!(is_required: true)
    issue = issue_with_secret(@field)
    issue.init_journal(User.find(2))
    issue.custom_field_values = {@field.id.to_s => {'action' => 'clear'}}
    assert_not issue.save
  end

  def test_plain_string_and_ciphertext_like_input_are_rejected
    issue = issue_with_secret(@field)
    stored = raw_value(issue, @field)
    forged = Cipher.encrypt('attacker', aad: aad(issue, @field))
    other_issue_ciphertext = raw_value(issue_with_secret(@field, issue_id: 2), @field)

    [SECRET, 'ecf:v1:k1:AAAA:AAAA:AAAA', forged, other_issue_ciphertext, ['a'], 123].each do |input|
      issue.reload
      issue.custom_field_values = {@field.id.to_s => input}
      assert_not issue.save, input.inspect
      assert_equal stored, raw_value(issue, @field)
    end
  end

  def test_invalid_hash_action_is_rejected
    issue = issue_with_secret(@field)
    issue.custom_field_values = {@field.id.to_s => {'action' => 'raw', 'encrypted_value' => 'x'}}
    assert_not issue.save
    issue.custom_field_values = {@field.id.to_s => {'action' => 'replace', 'encrypted_value' => ['x']}}
    assert_not issue.save
  end

  def test_regexp_and_length_validations_apply_to_plaintext
    @field.update!(regexp: '\A[a-z]+\z', max_length: 5)
    issue = Issue.find(1)
    issue.custom_field_values = {@field.id.to_s => replace_value('abcdefg')}
    assert_not issue.save
    issue.custom_field_values = {@field.id.to_s => replace_value('ABC')}
    assert_not issue.save
    issue.custom_field_values = {@field.id.to_s => replace_value('abc')}
    assert issue.save
  end

  def test_missing_key_is_a_validation_error_and_nothing_is_stored
    with_env(KEY_ENV => nil) do
      issue = Issue.find(1)
      issue.custom_field_values = {@field.id.to_s => replace_value}
      assert_not issue.save
      assert_includes issue.errors.full_messages.join, 'REDMINE_ENCRYPTED_FIELDS_KEY'
    end
    assert_nil raw_value(Issue.find(1), @field)
  end

  def test_raw_assignment_outside_the_format_is_encrypted
    issue = Issue.find(1)
    CustomValue.create!(customized: issue, custom_field: @field, value: SECRET)
    stored = raw_value(issue, @field)
    assert_not_equal SECRET, stored
    assert_equal SECRET, Cipher.decrypt(stored, aad: aad(issue, @field))
  end

  def test_ciphertext_moved_to_another_issue_cannot_be_decrypted
    issue = issue_with_secret(@field)
    stolen = raw_value(issue, @field)
    assert_raise(RedmineEncryptedCustomFields::DecryptionError) do
      Cipher.decrypt(stolen, aad: aad(Issue.find(2), @field))
    end
  end

  def test_pending_secret_never_shows_plaintext
    issue = Issue.find(1)
    issue.custom_field_values = {@field.id.to_s => replace_value}
    value = issue.custom_field_value(@field)
    assert_kind_of RedmineEncryptedCustomFields::PendingSecret, value
    assert_not_includes value.to_s, SECRET
    assert_not_includes value.inspect, SECRET
    assert_not_includes value.to_json, SECRET
    assert_not_includes issue.custom_field_values.inspect, SECRET
  end

  # 暗号化フィールドの値を変えない保存では、プラグインが editable の計算（クエリ）を足さない。
  def test_save_without_encrypted_changes_does_not_compute_editable_values
    issue = issue_with_secret(@field)
    issue.init_journal(User.find(2))
    issue.subject = 'not loaded'
    issue.expects(:editable_custom_field_values).never
    issue.save!

    issue = Issue.find(1)
    issue.init_journal(User.find(2))
    issue.custom_field_values # 読み込み済みでも、新しい値がなければ計算しない
    issue.subject = 'loaded'
    issue.expects(:editable_custom_field_values).never
    issue.save!
  end

  # -- 履歴 ------------------------------------------------------

  def test_journal_records_only_that_value_changed
    issue = issue_with_secret(@field)
    issue.init_journal(User.find(1))
    issue.custom_field_values = {@field.id.to_s => replace_value('second')}
    issue.save!

    details = JournalDetail.where(property: 'cf', prop_key: @field.id.to_s).to_a
    assert_equal 2, details.size
    assert_equal [nil, RedmineEncryptedCustomFields::MASK_TEXT], [details.first.old_value, details.first.value]
    assert_equal [RedmineEncryptedCustomFields::MASK_TEXT] * 2, [details.last.old_value, details.last.value]
    assert_not JournalDetail.where("value LIKE :s OR old_value LIKE :s OR value LIKE 'ecf:%' OR old_value LIKE 'ecf:%'", s: "%#{SECRET}%").exists?
  end

  def test_unchanged_value_creates_no_journal_detail
    issue = issue_with_secret(@field)
    issue.init_journal(User.find(1))
    issue.custom_field_values = {@field.id.to_s => {'action' => 'keep'}}
    issue.subject = 'other'
    assert_no_difference -> {JournalDetail.where(property: 'cf').count} do
      issue.save!
    end
  end

  # -- コピー ----------------------------------------------------

  def test_copy_does_not_copy_secret
    source = issue_with_secret(@field)
    User.current = User.find(2)
    copy = Issue.new.copy_from(source)
    assert copy.save, copy.errors.full_messages.inspect
    assert_equal '', raw_value(copy, @field).to_s
  end

  # -- 権限 ------------------------------------------------------

  def test_field_is_invisible_without_view_permission
    revoke(2, :view_encrypted_custom_fields)
    developer = User.find(3)
    assert_not @field.visible_by?(Project.find(1), developer)
    assert_not_includes Issue.find(1).visible_custom_field_values(developer).map(&:custom_field), @field

    grant(2, :view_encrypted_custom_fields)
    assert @field.visible_by?(Project.find(1), User.find(3))
  end

  def test_field_is_invisible_to_anonymous
    assert_not @field.visible_by?(Project.find(1), User.anonymous)
  end

  def test_field_role_visibility_still_applies
    grant(2, :view_encrypted_custom_fields)
    @field.update!(visible: false, role_ids: [1])
    assert_not @field.visible_by?(Project.find(1), User.find(3))
  end

  def test_field_is_read_only_without_edit_permission
    grant(2, :view_encrypted_custom_fields)
    developer = User.find(3)
    issue = Issue.find(1)
    assert_includes issue.read_only_attribute_names(developer), @field.id.to_s

    issue.init_journal(developer)
    issue.send(:safe_attributes=, {'custom_field_values' => {@field.id.to_s => replace_value}}, developer)
    issue.save!
    assert_nil raw_value(issue, @field)

    grant(2, :edit_encrypted_custom_fields)
    assert_not_includes Issue.find(1).read_only_attribute_names(User.find(3)), @field.id.to_s
  end

  # -- カスタムフィールドの定義 ----------------------------------

  def test_format_cannot_be_changed
    @field.field_format = 'string'
    @field.save!
    assert_equal 'encrypted_text', @field.reload.field_format

    string_field = IssueCustomField.create!(name: 'Plain', field_format: 'string', is_for_all: true)
    string_field.field_format = 'encrypted_text'
    string_field.save!
    assert_equal 'string', string_field.reload.field_format
  end

  def test_unsafe_options_are_disabled
    field = create_encrypted_field(name: 'Secret 2', is_filter: true, searchable: true, multiple: true)
    field.reload
    assert_not field.is_filter
    assert_not field.searchable
    assert_not field.multiple
    assert field.url_pattern.blank?
    assert_nil field.order_statement
    assert_nil field.group_statement
    assert_not field.totalable?
  end

  def test_url_pattern_is_not_allowed
    field = IssueCustomField.new(name: 'With URL', field_format: 'encrypted_text', is_for_all: true, visible: true, url_pattern: 'https://example.com/%value%')
    assert_not field.save
    assert field.errors[:url_pattern].any?
  end

  def test_default_value_is_not_allowed
    field = IssueCustomField.new(name: 'With default', field_format: 'encrypted_text', is_for_all: true, visible: true, default_value: SECRET)
    assert_not field.save
    assert_not CustomField.where("default_value LIKE ?", "%#{SECRET}%").exists?
  end

  def test_not_available_for_other_objects
    assert_includes Redmine::FieldFormat.as_select('Issue').map(&:last), 'encrypted_text'
    assert_not_includes Redmine::FieldFormat.as_select('Project').map(&:last), 'encrypted_text'
    assert_not_includes Redmine::FieldFormat.as_select('User').map(&:last), 'encrypted_text'
  end

  def test_query_has_no_filter_and_column_is_not_sortable
    issue_with_secret(@field)
    User.current = User.find(2)
    query = IssueQuery.new(project: Project.find(1))
    assert_not query.available_filters.key?("cf_#{@field.id}")
    column = query.available_columns.detect {|c| c.name == :"cf_#{@field.id}"}
    assert column
    assert_not column.sortable?
    assert_not column.groupable?
    assert_equal RedmineEncryptedCustomFields::MASK_TEXT, column.value(Issue.find(1))
  end

  # -- 回帰確認: 通常のカスタムフィールド ----------------------

  def test_string_custom_field_still_works
    field = IssueCustomField.create!(name: 'Plain', field_format: 'string', is_for_all: true, visible: true, tracker_ids: [1])
    issue = Issue.find(1)
    issue.init_journal(User.find(1))
    issue.custom_field_values = {field.id.to_s => 'hello'}
    issue.save!
    assert_equal 'hello', raw_value(issue, field)
    detail = JournalDetail.where(property: 'cf', prop_key: field.id.to_s).last
    assert_equal 'hello', detail.value
    assert field.visible_by?(Project.find(1), User.find(3))
  end
end
