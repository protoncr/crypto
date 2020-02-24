module TGCrypto
  module Padding
      # Performs padding on the given plaintext to ensure that it is a multiple
      # of the given block_size value in the parameter. Uses the PKCS7 standard
      # for performing padding.
      def self.pkcs7(buffer : Indexable(UInt8), block_size : Int)
        buffer = buffer.to_a
        no_blocks = (buffer.size / block_size).ceil
        pad_value = (no_blocks * block_size - buffer.size).to_i

        if buffer.size == block_size
          return buffer
        end

        if pad_value == 0
          buffer + ([block_size.to_u8] * block_size)
        else
          buffer + ([pad_value.to_u8] * pad_value)
        end
      end
  end
end
