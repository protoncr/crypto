# This module implements various block cipher modes.
#
# The six currently supported modes are:
#
# * ECB (Electronic Code Book)
# * CBC (Cipher Block Chaining)
# * CFB (Cipher FeedBack)
# * OFB (Output FeedBack)
# * IGE (Infinite Garbled Extension)
# * CTR (Counter)
# * GCM (Galois/Counter Mode)
#
# These modes can be used with any of the block cipher
# implementations in this library.

MAX_BLOCK_SIZE = 256
MAX_BLOCK_BYTES_SIZE = MAX_BLOCK_SIZE << 3

abstract class SHA2Context
end

macro make_sha_context(bits, block_size, type)
  class SHA{{bits}} < SHA2Context
    BITS = {{bits}}
    BLOCK_SIZE = {{block_size}}
    TYPE = {{type}}

    getter count : StaticArray({{type}}, 2) = StaticArray({{type}}, 2).new(0)
    getter state : StaticArray({{type}}, 8) = StaticArray({{type}}, 8).new(0)
    getter buffer : StaticArray(UInt8, {{block_size}}) = StaticArray(UInt8, {{block_size}}).new(0)

    def initialize
      self.reset
    end

    def reset
      {% if bits == 224 && block_size == 64 %}\
        self.state[0] = 0xC1059ED8_u32
        self.state[1] = 0x367CD507_u32
        self.state[2] = 0x3070DD17_u32
        self.state[3] = 0xF70E5939_u32
        self.state[4] = 0xFFC00B31_u32
        self.state[5] = 0x68581511_u32
        self.state[6] = 0x64F98FA7_u32
        self.state[7] = 0xBEFA4FA4_u32
      {% elsif bits == 256 && block_size == 64 %}\
        self.state[0] = 0x6A09E667_u32
        self.state[1] = 0xBB67AE85_u32
        self.state[2] = 0x3C6EF372_u32
        self.state[3] = 0xA54FF53A_u32
        self.state[4] = 0x510E527F_u32
        self.state[5] = 0x9B05688C_u32
        self.state[6] = 0x1F83D9AB_u32
        self.state[7] = 0x5BE0CD19_u32
      {% elsif bits == 384 && block_size == 128 %}\
        self.state[0] = 0xCBBB9D5DC1059ED8_u64
        self.state[1] = 0x629A292A367CD507_u64
        self.state[2] = 0x9159015A3070DD17_u64
        self.state[3] = 0x152FECD8F70E5939_u64
        self.state[4] = 0x67332667FFC00B31_u64
        self.state[5] = 0x8EB44A8768581511_u64
        self.state[6] = 0xDB0C2E0D64F98FA7_u64
        self.state[7] = 0x47B5481DBEFA4FA4_u64
      {% elsif bits == 512 && block_size == 128 %}\
        self.state[0] = 0x6A09E667F3BCC908_u64
        self.state[1] = 0xBB67AE8584CAA73B_u64
        self.state[2] = 0x3C6EF372FE94F82B_u64
        self.state[3] = 0xA54FF53A5F1D36F1_u64
        self.state[4] = 0x510E527FADE682D1_u64
        self.state[5] = 0x9B05688C2B3E6C1F_u64
        self.state[6] = 0x1F83D9ABFB41BD6B_u64
        self.state[7] = 0x5BE0CD19137E2179_u64
      {% elsif bits == 224 && block_size == 128 %}\
        self.state[0] = 0x8C3D37C819544DA2_u64
        self.state[1] = 0x73E1996689DCD4D6_u64
        self.state[2] = 0x1DFAB7AE32FF9C82_u64
        self.state[3] = 0x679DD514582F9FCF_u64
        self.state[4] = 0x0F6D2B697BD44DA8_u64
        self.state[5] = 0x77E36F7304C48942_u64
        self.state[6] = 0x3F9D85A86A1D36C8_u64
        self.state[7] = 0x1112E6AD91D692A1_u64
      {% elsif bits == 256 && block_size == 128 %}\
        self.state[0] = 0x22312194FC2BF72C_u64
        self.state[1] = 0x9F555FA3C84C64C2_u64
        self.state[2] = 0x2393B86B6F53B151_u64
        self.state[3] = 0x963877195940EABD_u64
        self.state[4] = 0x96283EE2A88EFFE3_u64
        self.state[5] = 0xBE5E1E2553863992_u64
        self.state[6] = 0x2B0199FC2C85B8AA_u64
        self.state[7] = 0x0EB72DDC81C52CA2_u64
      {% else %}\
        {% raise "bit size to block size mismatch" %}
      {% end %}
    end

    def clear
      self.state.map { {{type}}.new(0) }
      self.buffer.map { {{type}}.new(0) }
    end

    private def transform(arr : Array({{type}}), data : Indexable(UInt8))
      {% if bits == 256 %}

      {% elsif bits == 512 %}

      {% else %}
    end
  end
end

abstract class BlockMode(T)
end

class ECB(T) < BlockMode(T)
  def initialize(key : Pointer(UInt8))
    if key.null?
      raise "key cannot be a null pointer"
    end

    if T.block_size > MAX_BLOCK_SIZE
      raise "context block size too large"
    end

    cipher = T.new(key)
  end
end
