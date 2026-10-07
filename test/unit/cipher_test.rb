# frozen_string_literal: true

require_relative '../test_helper'

class EncryptedCustomFieldsCipherTest < ActiveSupport::TestCase
  include EncryptedCustomFieldsTestHelper

  Cipher = RedmineEncryptedCustomFields::Cipher
  AAD = 'Issue:1:CustomField:99'

  def setup
    setup_encryption_key
  end

  def teardown
    restore_encryption_key
  end

  def test_round_trip
    stored = Cipher.encrypt(SECRET, aad: AAD)
    assert_not_includes stored, SECRET
    assert_match /\Aecf:v1:k1:/, stored
    assert_equal SECRET, Cipher.decrypt(stored, aad: AAD)
  end

  def test_round_trip_multibyte
    assert_equal 'パスワード🔑', Cipher.decrypt(Cipher.encrypt('パスワード🔑', aad: AAD), aad: AAD)
  end

  def test_nonce_and_ciphertext_differ_for_same_input
    a = Cipher.encrypt(SECRET, aad: AAD).split(':')
    b = Cipher.encrypt(SECRET, aad: AAD).split(':')
    assert_not_equal a[3], b[3], 'nonce must be random'
    assert_not_equal a[4], b[4]
  end

  def test_tampered_ciphertext_fails
    parts = Cipher.encrypt(SECRET, aad: AAD).split(':')
    bytes = Cipher.decode(parts[4])
    bytes.setbyte(0, bytes.getbyte(0) ^ 1)
    parts[4] = Cipher.encode(bytes)
    assert_raise(RedmineEncryptedCustomFields::DecryptionError) {Cipher.decrypt(parts.join(':'), aad: AAD)}
  end

  def test_tampered_tag_fails
    parts = Cipher.encrypt(SECRET, aad: AAD).split(':')
    tag = Cipher.decode(parts[5])
    tag.setbyte(15, tag.getbyte(15) ^ 1)
    parts[5] = Cipher.encode(tag)
    assert_raise(RedmineEncryptedCustomFields::DecryptionError) {Cipher.decrypt(parts.join(':'), aad: AAD)}
  end

  def test_truncated_tag_is_rejected
    parts = Cipher.encrypt(SECRET, aad: AAD).split(':')
    parts[5] = Cipher.encode(Cipher.decode(parts[5])[0, 4])
    assert_raise(RedmineEncryptedCustomFields::DecryptionError) {Cipher.decrypt(parts.join(':'), aad: AAD)}
  end

  def test_other_issue_or_field_fails
    stored = Cipher.encrypt(SECRET, aad: AAD)
    assert_raise(RedmineEncryptedCustomFields::DecryptionError) {Cipher.decrypt(stored, aad: 'Issue:2:CustomField:99')}
    assert_raise(RedmineEncryptedCustomFields::DecryptionError) {Cipher.decrypt(stored, aad: 'Issue:1:CustomField:98')}
  end

  def test_wrong_key_fails
    stored = Cipher.encrypt(SECRET, aad: AAD)
    with_env(KEY_ENV => OTHER_KEY) do
      assert_raise(RedmineEncryptedCustomFields::DecryptionError) {Cipher.decrypt(stored, aad: AAD)}
    end
  end

  def test_key_id_is_authenticated
    stored = Cipher.encrypt(SECRET, aad: AAD)
    with_env(KEY_ID_ENV => 'k2') do
      assert_raise(RedmineEncryptedCustomFields::UnknownKeyError) {Cipher.decrypt(stored, aad: AAD)}
      forged = stored.sub(':k1:', ':k2:')
      assert_raise(RedmineEncryptedCustomFields::DecryptionError) {Cipher.decrypt(forged, aad: AAD)}
    end
  end

  def test_missing_key_fails_closed
    with_env(KEY_ENV => nil) do
      assert_raise(RedmineEncryptedCustomFields::KeyNotConfiguredError) {Cipher.encrypt(SECRET, aad: AAD)}
    end
    stored = Cipher.encrypt(SECRET, aad: AAD)
    with_env(KEY_ENV => '') do
      assert_raise(RedmineEncryptedCustomFields::KeyNotConfiguredError) {Cipher.decrypt(stored, aad: AAD)}
    end
  end

  def test_invalid_keys_are_rejected
    [
      'not base64!!',
      Base64.strict_encode64('short'),
      Base64.strict_encode64('x' * 33),
      "#{TEST_KEY}\n",
      " #{TEST_KEY}"
    ].each do |bad|
      with_env(KEY_ENV => bad) do
        assert_raise(RedmineEncryptedCustomFields::InvalidKeyError, bad.inspect) {Cipher.encrypt(SECRET, aad: AAD)}
      end
    end
  end

  def test_invalid_key_id_is_rejected
    with_env(KEY_ID_ENV => 'K1:x') do
      assert_raise(RedmineEncryptedCustomFields::InvalidKeyError) {Cipher.encrypt(SECRET, aad: AAD)}
    end
  end

  def test_error_messages_do_not_contain_secrets
    stored = Cipher.encrypt(SECRET, aad: AAD)
    error = assert_raise(RedmineEncryptedCustomFields::DecryptionError) {Cipher.decrypt(stored, aad: 'Issue:2:CustomField:1')}
    assert_not_includes error.message, SECRET
    assert_not_includes error.message, stored
    assert_not_includes error.message, TEST_KEY
  end

  def test_unknown_formats_are_rejected
    ['', SECRET, 'enc:v1:abc', 'ecf:v1:k1:', 'ecf:v2:k1:AAAA:AAAA:AAAA', 'ecf:v1:k1:!!:AA:AA'].each do |value|
      assert_raise(RedmineEncryptedCustomFields::DecryptionError, value) {Cipher.decrypt(value, aad: AAD)}
    end
  end
end
