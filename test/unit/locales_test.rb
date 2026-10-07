# frozen_string_literal: true

require_relative '../test_helper'

# プラグインが参照する翻訳キーが en / ja の両方に存在することを確認する
# （Redmine 本体のキーを含む）。
class EncryptedCustomFieldsLocalesTest < ActiveSupport::TestCase
  PLUGIN_ROOT = File.expand_path('../..', __dir__)
  SOURCES = Dir[File.join(PLUGIN_ROOT, '{app,lib}', '**', '*.{rb,erb}')] + [File.join(PLUGIN_ROOT, 'init.rb')]

  # 動的に組み立てているキー
  DYNAMIC_KEYS =
    EncryptedCustomFieldAuditLog::ACTIONS.map {|action| "label_ecf_action_#{action}"} +
    %w(label_encrypted_text permission_view_encrypted_custom_fields
       permission_reveal_encrypted_custom_fields permission_edit_encrypted_custom_fields)

  def referenced_keys
    keys = SOURCES.flat_map do |path|
      File.read(path).scan(/\b(?:l|I18n\.t)\(:([a-z_]+)\)|render_ecf_error\(:([a-z_]+)|\breject\([^,]+,[^,]+,\s*:([a-z_]+)\)|\bcaption:\s*:([a-z_]+)/).flatten.compact
    end
    (keys + DYNAMIC_KEYS).uniq.sort
  end

  def test_referenced_keys_exist_in_en_and_ja
    keys = referenced_keys
    assert_operator keys.size, :>, 20
    %w(en ja).each do |locale|
      missing = keys.reject {|key| I18n.exists?(key, locale.to_sym)}
      assert_empty missing, "missing #{locale} translations"
    end
  end

  def test_plugin_locales_have_same_keys
    en = YAML.load_file(File.join(PLUGIN_ROOT, 'config/locales/en.yml'))['en'].keys
    ja = YAML.load_file(File.join(PLUGIN_ROOT, 'config/locales/ja.yml'))['ja'].keys
    assert_equal en.sort, ja.sort
  end
end
