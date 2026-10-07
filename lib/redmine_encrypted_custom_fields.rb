# frozen_string_literal: true

module RedmineEncryptedCustomFields
  VERSION = '0.1.0'

  FORMAT_NAME = 'encrypted_text'

  # 固定長のマスク。秘密の値の長さも明かさない。
  MASK_TEXT = '********'
  MASK_HTML = "•" * 8

  # 新しい平文を運ぶフォーム / API のキー名。Rails の filter_parameters に追加し、
  # リクエストログに値が出ないようにする。
  SECRET_PARAM = 'encrypted_value'

  # エラーメッセージには値・鍵・暗号文を含めない。
  class Error < StandardError; end
  class KeyNotConfiguredError < Error; end
  class InvalidKeyError < Error; end
  class UnknownKeyError < Error; end
  class DecryptionError < Error; end

  class << self
    attr_writer :key_provider

    def key_provider
      @key_provider ||= EnvironmentKeyProvider.new
    end

    def encrypted_field?(custom_field)
      custom_field.respond_to?(:field_format) && custom_field.field_format == FORMAT_NAME
    end

    # init.rb から呼ばれる。Redmine はコードを再読み込みするたびに init.rb を実行する。
    def setup
      # これらのクラスを読み込むと、フィールド形式とビューフックが登録される。
      Redmine::FieldFormat.add(FORMAT_NAME, EncryptedTextFormat)
      Hooks.instance

      apply_patch(CustomValue, Patches::CustomValuePatch)
      apply_patch(Issue, Patches::IssuePatch)
      apply_patch(IssueCustomField, Patches::IssueCustomFieldPatch)
      apply_patch(Journal, Patches::JournalPatch)
      apply_patch(CustomFieldsHelper, Patches::CustomFieldsHelperPatch)
      apply_patch(IssuesController, Patches::IssuesControllerPatch)

      add_parameter_filter
      warn_if_key_misconfigured
    end

    private

    def apply_patch(target, patch)
      target.prepend(patch) unless target.ancestors.include?(patch)
    end

    # 配列そのものに追加する。リクエストのパラメータフィルタ
    # （env_config["action_dispatch.parameter_filter"]）は同じ配列を参照している。
    def add_parameter_filter
      filters = Rails.application.config.filter_parameters
      filters << SECRET_PARAM unless filters.include?(SECRET_PARAM)
    end

    def warn_if_key_misconfigured
      key_provider.validate!
    rescue Error => e
      # Redmine の起動は止めない。鍵が直るまで、暗号化フィールドの保存と復号を拒否するだけ。
      Rails.logger&.warn "[redmine_encrypted_custom_fields] #{e.message}"
    end
  end
end
