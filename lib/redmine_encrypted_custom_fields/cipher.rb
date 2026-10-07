# frozen_string_literal: true

require 'base64'
require 'openssl'
require 'securerandom'

module RedmineEncryptedCustomFields
  # カスタムフィールドの値を AES-256-GCM で暗号化・復号する。
  #
  # 保存形式（custom_values.value の 1 カラムに収まる）:
  #
  #   ecf:v1:<鍵ID>:<nonce>:<暗号文>:<tag>     （Base64url、パディングなし）
  #
  # 認証付き追加データ（AAD）で暗号文を形式バージョン・鍵 ID・所有オブジェクト・
  # カスタムフィールドに紐付ける。DB の改ざんなどで別のチケットやフィールドへ
  # 暗号文をコピーしても、認証に失敗して復号できない。
  module Cipher
    ALGORITHM = 'aes-256-gcm'
    PREFIX = 'ecf'
    FORMAT_VERSION = 'v1'
    NONCE_BYTES = 12
    TAG_BYTES = 16
    B64 = '[A-Za-z0-9_-]'
    STORED_FORMAT = /\A#{PREFIX}:(#{FORMAT_VERSION}):([a-z0-9]{1,16}):(#{B64}+):(#{B64}*):(#{B64}+)\z/

    module_function

    def aad_for(owner_type, owner_id, custom_field_id)
      raise Error, 'Cannot encrypt a value for an unsaved object' if owner_id.blank? || custom_field_id.blank?

      "#{owner_type}:#{Integer(owner_id)}:CustomField:#{Integer(custom_field_id)}"
    end

    def encrypt(plaintext, aad:, key_provider: RedmineEncryptedCustomFields.key_provider)
      raise ArgumentError, 'plaintext must be a String' unless plaintext.is_a?(String)

      key_id = key_provider.current_key_id
      cipher = OpenSSL::Cipher.new(ALGORITHM).encrypt
      cipher.key = key_provider.key_for(key_id)
      nonce = SecureRandom.random_bytes(NONCE_BYTES)
      cipher.iv = nonce
      cipher.auth_data = auth_data(FORMAT_VERSION, key_id, aad)
      ciphertext = cipher.update(plaintext.encode(Encoding::UTF_8).b) + cipher.final
      tag = cipher.auth_tag(TAG_BYTES)

      [PREFIX, FORMAT_VERSION, key_id, encode(nonce), encode(ciphertext), encode(tag)].join(':')
    end

    def decrypt(stored, aad:, key_provider: RedmineEncryptedCustomFields.key_provider)
      match = STORED_FORMAT.match(stored.to_s)
      raise DecryptionError, 'Unrecognized ciphertext format' unless match

      version, key_id, nonce, ciphertext, tag = match.captures
      key = key_provider.key_for(key_id)
      nonce = decode(nonce)
      ciphertext = decode(ciphertext)
      tag = decode(tag)
      # OpenSSL は切り詰められたタグも受け付けてしまい、認証が弱くなるため長さを確認する。
      raise DecryptionError, 'Invalid nonce or tag length' unless nonce.bytesize == NONCE_BYTES && tag.bytesize == TAG_BYTES

      cipher = OpenSSL::Cipher.new(ALGORITHM).decrypt
      cipher.key = key
      cipher.iv = nonce
      cipher.auth_tag = tag
      cipher.auth_data = auth_data(version, key_id, aad)
      plaintext = (cipher.update(ciphertext) + cipher.final).force_encoding(Encoding::UTF_8)
      raise DecryptionError, 'Decrypted value is not valid UTF-8' unless plaintext.valid_encoding?

      plaintext
    rescue OpenSSL::Cipher::CipherError
      raise DecryptionError, 'Ciphertext authentication failed'
    end

    # 文字列が保存形式の見た目をしているかどうかを返すだけ。
    # ユーザー入力を「暗号化済み」と信用する判定には絶対に使わないこと。
    def stored_format?(value)
      value.is_a?(String) && STORED_FORMAT.match?(value)
    end

    def auth_data(version, key_id, aad)
      "#{PREFIX}:#{version}:#{key_id}|#{aad}"
    end

    def encode(bytes)
      Base64.urlsafe_encode64(bytes, padding: false)
    end

    def decode(text)
      Base64.urlsafe_decode64(text)
    rescue ArgumentError
      raise DecryptionError, 'Invalid Base64 in ciphertext'
    end
  end
end
