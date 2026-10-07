# frozen_string_literal: true

module RedmineEncryptedCustomFields
  # カスタムフィールド形式「暗号化テキスト」（チケット専用）。
  #
  # メモリ上の CustomFieldValue#value は次のどちらかで、平文の String にはならない:
  #   * 保存済みの暗号文の String（未設定なら '' または nil）
  #   * チケットを保存するまで新しい平文を保持する PendingSecret
  #
  # 受け付ける入力（フォーム、API、他プラグイン）:
  #   {'action' => 'keep'}                               保存済みの値を維持
  #   {'action' => 'replace', 'encrypted_value' => 'x'}  新しい値を保存
  #   {'action' => 'clear'}                              値を削除
  #   {'encrypted_value' => 'x'}                         replace と同じ
  #   '' / nil / マスク / 変更されていない保存値          維持
  # それ以外の平文の String はバリデーションエラーで拒否する。受け付けてしまうと、
  # マスクや暗号文のように見える値で秘密の値が上書きされたり、
  # パラメータログのフィルタをすり抜けられたりするため。
  class EncryptedTextFormat < Redmine::FieldFormat::Unbounded
    add FORMAT_NAME

    self.customized_class_names = %w(Issue)
    self.multiple_supported = false
    self.searchable_supported = false
    self.is_filter_supported = false
    self.totalable_supported = false
    self.bulk_edit_supported = false
    # 履歴と通知には「<フィールド名>が更新されました」とだけ出す。
    self.change_no_details = true
    self.form_partial = 'custom_fields/formats/encrypted_text'

    ACTIONS = %w(keep replace clear).freeze
    REJECTION = :@ecf_rejection

    def label
      'label_encrypted_text'
    end

    # -- カスタムフィールドの定義 -------------------------------------------

    def before_custom_field_save(custom_field)
      # デフォルト値とリンク URL は平文で保存されてしまうため使わせない。
      custom_field.default_value = nil
      custom_field.url_pattern = nil
      custom_field.is_filter = false
      custom_field.searchable = false
      custom_field.multiple = false
    end

    def validate_custom_field(custom_field)
      errors = super
      errors << [:default_value, :invalid] if custom_field.default_value.present?
      errors << [:url_pattern, :invalid] if custom_field.url_pattern.present?
      errors
    end

    # -- 入力 ---------------------------------------------------------------

    def set_custom_field_value(custom_field, custom_field_value, value)
      custom_field_value.instance_variable_set(REJECTION, nil)
      current = custom_field_value.value

      case value
      when PendingSecret
        value
      when Hash, ActionController::Parameters
        value_from_hash(custom_field_value, current, value)
      when nil
        current
      when String
        if value.empty? || value == MASK_TEXT || (current.is_a?(String) && value == current)
          current
        else
          reject(custom_field_value, current, :error_ecf_plain_value)
        end
      else
        reject(custom_field_value, current, :error_ecf_plain_value)
      end
    end

    def validate_custom_value(custom_value)
      errors = []
      if (rejection = custom_value.instance_variable_get(REJECTION))
        errors << ::I18n.t(rejection)
      end
      value = custom_value.value
      if value.is_a?(PendingSecret)
        errors.concat(validate_single_value(custom_value.custom_field, value.plaintext, custom_value.customized))
        errors << ::I18n.t(:error_ecf_key_not_configured) unless RedmineEncryptedCustomFields.key_provider.configured?
      end
      errors.uniq
    end

    # -- 出力: 常にマスク。平文も暗号文も出さない --------------------------

    def cast_single_value(custom_field, value, customized=nil)
      MASK_TEXT
    end

    def formatted_value(view, custom_field, value, customized=nil, html=false)
      return '' if value.blank?

      html ? MASK_HTML : MASK_TEXT
    end

    def formatted_custom_value(view, custom_value, html=false)
      return '' if custom_value.value.blank?
      return MASK_TEXT unless html

      masked_html(view, custom_value)
    end

    def edit_tag(view, tag_id, tag_name, custom_value, options={})
      view.render(
        partial: 'encrypted_custom_fields/edit_tag',
        locals: {
          tag_id: tag_id,
          tag_name: tag_name,
          custom_value: custom_value,
          stored: custom_value.respond_to?(:value_was) && custom_value.value_was.present?,
          pending: custom_value.value.is_a?(PendingSecret),
          input_class: options[:class]
        }
      )
    end

    def bulk_edit_tag(view, tag_id, tag_name, custom_field, objects, value, options={})
      ''.html_safe
    end

    # 暗号文での並び替え・グループ化・集計は意味がないうえ、順序の情報が漏れうるため無効にする。
    def order_statement(custom_field)
      nil
    end

    def group_statement(custom_field)
      nil
    end

    def join_for_order_statement(custom_field)
      nil
    end

    private

    def value_from_hash(custom_field_value, current, value)
      hash = value.respond_to?(:to_unsafe_h) ? value.to_unsafe_h : value
      hash = hash.stringify_keys
      action = hash['action'].to_s
      secret = hash[SECRET_PARAM]
      return reject(custom_field_value, current, :error_ecf_plain_value) unless secret.nil? || secret.is_a?(String)

      case action
      when 'keep'
        current
      when 'clear'
        ''
      when 'replace', ''
        if secret.present?
          PendingSecret.new(secret)
        elsif action == 'replace'
          reject(custom_field_value, current, :error_ecf_blank_replacement)
        else
          current
        end
      else
        reject(custom_field_value, current, :error_ecf_plain_value)
      end
    end

    # 現在の値を維持し、バリデーションエラーを記録する。
    def reject(custom_field_value, current, message)
      custom_field_value.instance_variable_set(REJECTION, message)
      current
    end

    def masked_html(view, custom_value)
      issue = custom_value.customized
      custom_field = custom_value.custom_field
      reveal = view.controller_name == 'issues' && view.action_name == 'show' &&
               custom_value.value.is_a?(String) &&
               Permissions.reveal?(User.current, issue, custom_field)

      view.render(
        partial: 'encrypted_custom_fields/masked_value',
        locals: {
          reveal_url: reveal ? view.reveal_issue_encrypted_custom_field_path(issue_id: issue.id, custom_field_id: custom_field.id) : nil
        }
      )
    end
  end
end
