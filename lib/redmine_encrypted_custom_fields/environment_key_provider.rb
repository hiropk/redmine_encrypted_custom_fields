# frozen_string_literal: true

require 'base64'

module RedmineEncryptedCustomFields
  # REDMINE_ENCRYPTED_FIELDS_KEY（ちょうど 32 バイトの乱数を厳密な Base64 にしたもの）から
  # 鍵を読む。プラグイン内で鍵をキャッシュしないよう、呼ばれるたびに環境変数を読む。
  class EnvironmentKeyProvider < KeyProvider
    KEY_ENV = 'REDMINE_ENCRYPTED_FIELDS_KEY'
    KEY_ID_ENV = 'REDMINE_ENCRYPTED_FIELDS_KEY_ID'
    DEFAULT_KEY_ID = 'k1'

    def initialize(env = ENV)
      super()
      @env = env
    end

    def current_key_id
      key_id = @env[KEY_ID_ENV]
      return DEFAULT_KEY_ID if key_id.blank?
      raise InvalidKeyError, "#{KEY_ID_ENV} must match #{KEY_ID_FORMAT.source}" unless KEY_ID_FORMAT.match?(key_id)

      key_id
    end

    def key_for(key_id)
      raise UnknownKeyError, 'Ciphertext was sealed with an unknown key id' unless key_id == current_key_id

      decode(@env[KEY_ENV])
    end

    private

    def decode(encoded)
      raise KeyNotConfiguredError, "#{KEY_ENV} is not set" if encoded.blank?

      key =
        begin
          Base64.strict_decode64(encoded)
        rescue ArgumentError
          raise InvalidKeyError, "#{KEY_ENV} is not valid Base64"
        end
      raise InvalidKeyError, "#{KEY_ENV} must decode to #{KEY_BYTES} bytes" unless key.bytesize == KEY_BYTES

      key
    end
  end
end
