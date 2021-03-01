require "./aes"

module Crypto
  module IGE
    # Encrypt a buffer using IGE256.
    #
    # `data` must be a non-empty buffer who's length is a multiple
    # of 16 bytes. `key` and `iv` must each contain 32 bytes.
    def self.encrypt(data : Bytes, key : Bytes, iv : Bytes) : Bytes
      self.xcrypt(data, key, iv, true)
    end

    # Decrypt a buffer using IGE256.
    #
    # `data` must be a non-empty buffer who's length is a multiple
    # of 16 bytes. `key` and `iv` must each contain 32 bytes.
    def self.decrypt(data : Bytes, key : Bytes, iv : Bytes) : Bytes
      self.xcrypt(data, key, iv, false)
    end

    private def self.xcrypt(data : Bytes, key : Bytes, iv : Bytes, encrypt : Bool) : Bytes
      unless data.size > 0
        raise "data must not be empty"
      end

      unless data.size % 16 == 0
        raise "data byte size must be a multiple of 16"
      end

      unless key.size == 32
        raise "key byte size must be 32 bytes exactly"
      end

      unless iv.size == 32
        raise "iv byte size must be 32 bytes exactly"
      end

      output = data.clone
      key = key.clone
      iv = iv.clone

      chunk = Bytes.new(AES::BLOCK_SIZE)
      buffer = Bytes.new(AES::BLOCK_SIZE)

      expanded_key = encrypt ? AES.create_encryption_key(key) : AES.create_decryption_key(key)

      iv1 = encrypt ? iv[0, AES::BLOCK_SIZE] : iv[AES::BLOCK_SIZE, AES::BLOCK_SIZE]

      iv2 = encrypt ? iv[AES::BLOCK_SIZE, AES::BLOCK_SIZE] : iv[0, AES::BLOCK_SIZE]

      (0...data.size).step(AES::BLOCK_SIZE).each do |i|
        data[i ... (i + AES::BLOCK_SIZE)].copy_to(chunk)

        (0...AES::BLOCK_SIZE).each do |j|
          buffer[j] = data[i + j] ^ iv1[j]
        end

        modded = encrypt ? AES.encrypt(buffer, expanded_key) : AES.decrypt(buffer, expanded_key)
        modded.copy_to(output[i ... (i + AES::BLOCK_SIZE)])

        (0...AES::BLOCK_SIZE).each do |j|
          output[i + j] ^= iv2[j]
        end

        output[i ... (i + AES::BLOCK_SIZE)].copy_to(iv1)
        chunk.copy_to(iv2)
      end

      output
    end
  end
end
