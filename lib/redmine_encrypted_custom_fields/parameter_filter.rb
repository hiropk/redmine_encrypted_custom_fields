# frozen_string_literal: true

module RedmineEncryptedCustomFields
  # リクエストログ（Rails の filter_parameters）から暗号化フィールドの値を伏せる。
  #
  # 決められた形式（encrypted_value）で送られた値はキー名だけで伏せられるが、
  # 次のような平文の送信はバリデーションで拒否する前にログへ出てしまう:
  #   issue[custom_field_values][8]=平文                       （フォーム）
  #   {"issue": {"custom_fields": [{"id": 8, "value": "平文"}]}}  （REST API）
  # キー名からは暗号化フィールドかどうか分からないため、フィールド ID で判定する。
  #
  # Rails はリーフの値ごとに call(key, value, original_params) を呼び、
  # value を書き換えるとログ上の値が置き換わる。
  module ParameterFilter
    MASK = '[FILTERED]'
    NUMERIC_KEY = /\A\d+\z/

    module_function

    def call(key, value, original_params)
      return unless value.is_a?(String) && !value.empty?

      key = key.to_s
      ids =
        if NUMERIC_KEY.match?(key)
          encrypted_field_ids(original_params)
        elsif key == 'value'
          encrypted_values_in_custom_fields_arrays(original_params)
        end
      return unless ids

      masked = key == 'value' ? ids.include?(value) : ids.include?(key)
      value.replace(MASK) if masked
    end

    # 同じリクエストの中では 1 回だけ問い合わせる。DB に問い合わせられないときは
    # 伏せる側に倒す（数値キーの値をすべて伏せる）。
    def encrypted_field_ids(original_params)
      cache = Thread.current[:redmine_encrypted_custom_fields_filter]
      return cache[1] if cache && cache[0].equal?(original_params)

      ids =
        begin
          CustomField.where(field_format: FORMAT_NAME).pluck(:id).to_set(&:to_s)
        rescue StandardError
          AnyId
        end
      Thread.current[:redmine_encrypted_custom_fields_filter] = [original_params, ids]
      ids
    end

    # custom_fields: [{id:, value:}] の配列から、暗号化フィールドの value を集める。
    def encrypted_values_in_custom_fields_arrays(original_params)
      arrays = []
      collect_custom_fields_arrays(original_params, arrays, 0)
      return if arrays.empty?

      ids = encrypted_field_ids(original_params)
      arrays.flatten.filter_map do |item|
        next unless item.respond_to?(:[]) && !item.is_a?(String)

        id = item['id'] || item[:id]
        value = item['value'] || item[:value]
        value if value.is_a?(String) && ids.include?(id.to_s)
      end
    end

    def collect_custom_fields_arrays(node, arrays, depth)
      return if depth > 4

      case node
      when Hash
        node.each do |k, v|
          arrays << v if k.to_s == 'custom_fields' && v.is_a?(Array)
          collect_custom_fields_arrays(v, arrays, depth + 1)
        end
      when Array
        node.each {|v| collect_custom_fields_arrays(v, arrays, depth + 1)}
      end
    end

    # DB に問い合わせられなかったときの「すべての ID が暗号化フィールド」扱い。
    module AnyId
      def self.include?(_id)
        true
      end
    end
  end
end
