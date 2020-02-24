require "./aes"

module TGCrypto
  module IGE
    # Encrypt a buffer using IGE256.
    #
    # `data` must be a non-empty buffer who's length is a multiple
    # of 16 bytes. `key` and `iv` must each contain 32 bytes.
    def self.encrypt(data : Indexable(UInt8), key : Indexable(UInt8), iv : Indexable(UInt8)) : Array(UInt8)
      self.xcrypt(data, key, iv, true)
    end

    # Decrypt a buffer using IGE256.
    #
    # `data` must be a non-empty buffer who's length is a multiple
    # of 16 bytes. `key` and `iv` must each contain 32 bytes.
    def self.decrypt(data : Indexable(UInt8), key : Indexable(UInt8), iv : Indexable(UInt8)) : Array(UInt8)
      self.xcrypt(data, key, iv, false)
    end

    private def self.xcrypt(data : Indexable(UInt8), key : Indexable(UInt8), iv : Indexable(UInt8), encrypt : Bool) : Array(UInt8)
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

      output = data.dup.as(Array(UInt8))
      chunk = Array(UInt8).new(AES::BLOCK_SIZE, 0)
      buffer = Array(UInt8).new(AES::BLOCK_SIZE, 0)

      expanded_key = encrypt ?
        AES.create_encryption_key(key) :
        AES.create_decryption_key(key)

      iv1 = encrypt ?
        iv[0, AES::BLOCK_SIZE] :
        iv[AES::BLOCK_SIZE, AES::BLOCK_SIZE]

      iv2 = encrypt ?
        iv[AES::BLOCK_SIZE, AES::BLOCK_SIZE] :
        iv[0, AES::BLOCK_SIZE]

      (0...data.size).step(AES::BLOCK_SIZE).each do |i|
        chunk = data[i, AES::BLOCK_SIZE]

        (0...AES::BLOCK_SIZE).each do |j|
          buffer[j] = data[i + j] ^ iv1[j]
        end

        output[i, AES::BLOCK_SIZE] = encrypt ?
          AES.encrypt(buffer, expanded_key) :
          AES.decrypt(buffer, expanded_key)

        (0...AES::BLOCK_SIZE).each do |j|
          output[i + j] ^= iv2[j]
        end

        iv1 = output[i, AES::BLOCK_SIZE]
        iv2 = chunk
      end

      output
    end
  end
end
