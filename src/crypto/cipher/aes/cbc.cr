require "./aes"

module Crypto
  module CBC
    # Encrypt a buffer using CBC256.
    #
    # `data` must be a non-empty buffer of any length.
    # `key` must be a 32 byte encryption key and `iv` must
    # be 16 bytes.
    def self.encrypt(data : Bytes, key : Bytes, iv : Bytes) : Bytes
      self.xcrypt(data, key, iv, true)
    end

    # Decrypt a buffer using CBC256.
    #
    # `data` must be a non-empty buffer of any length.
    # `key` must be a 32 byte encryption key and `iv` must
    # be 16 bytes.
    def self.decrypt(data : Bytes, key : Bytes, iv : Bytes) : Bytes
      self.xcrypt(data, key, iv, false)
    end

    private def self.xcrypt(data : Bytes, key : Bytes, iv : Bytes, encrypt : Bool) : Bytes
      unless data.size > 0
        raise "data must not be empty"
      end

      unless key.size == 32
        raise "key byte size must be 32 bytes exactly"
      end

      unless iv.size == 16
        raise "iv byte size must be 16 bytes exactly"
      end

      output = data.clone
      key = key.clone
      iv = iv.clone
      expanded_key = encrypt ? AES.create_encryption_key(key) : AES.create_decryption_key(key)

      if encrypt
        (0...data.size).step(AES::BLOCK_SIZE).each do |i|
          (0...AES::BLOCK_SIZE).each do |j|
            output[i + j] ^= iv[j]
          end
          encrypted = AES.encrypt(output[i, AES::BLOCK_SIZE], expanded_key)
          (output + i).copy_from(encrypted)
          iv = encrypted
        end
      else
        next_iv = Bytes.new(AES::BLOCK_SIZE)

        (0...data.size).step(AES::BLOCK_SIZE).each do |i|
          output[i, AES::BLOCK_SIZE].copy_to(next_iv)

          decrypted = AES.decrypt(output[i, AES::BLOCK_SIZE], expanded_key)
          (output + i).copy_from(decrypted)

          (0...AES::BLOCK_SIZE).each do |j|
            output[i + j] ^= iv[j]
          end

          next_iv.copy_to(iv)
        end
      end

      output
    end
  end
end
