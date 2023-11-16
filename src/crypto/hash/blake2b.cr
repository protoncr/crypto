module Crypto
  class Blake2b
    BLOCK_SIZE = 128
    SIZE = 64
    SIZE384 = 48
    SIZE256 = 32

    MAGIC = "b2b"
    MARSHALED_SIZE = MAGIC.size + 8*8 + 2*8 + 1 + BLOCK_SIZE + 1

    IV = Slice[
      0x6a09e667f3bcc908_u64, 0xbb67ae8584caa73b_u64, 0x3c6ef372fe94f82b_u64, 0xa54ff53a5f1d36f1_u64,
      0x510e527fade682d1_u64, 0x9b05688c2b3e6c1f_u64, 0x1f83d9abfb41bd6b_u64, 0x5be0cd19137e2179_u64,
    ]

    SIGMA = Slice[
      Slice[0_u8, 2_u8, 4_u8, 6_u8, 1_u8, 3_u8, 5_u8, 7_u8, 8_u8, 10_u8, 12_u8, 14_u8, 9_u8, 11_u8, 13_u8, 15_u8],
      Slice[14_u8, 4_u8, 9_u8, 13_u8, 10_u8, 8_u8, 15_u8, 6_u8, 1_u8, 0_u8, 11_u8, 5_u8, 12_u8, 2_u8, 7_u8, 3_u8],
      Slice[11_u8, 12_u8, 5_u8, 15_u8, 8_u8, 0_u8, 2_u8, 13_u8, 10_u8, 3_u8, 7_u8, 9_u8, 14_u8, 6_u8, 1_u8, 4_u8],
      Slice[7_u8, 3_u8, 13_u8, 11_u8, 9_u8, 1_u8, 12_u8, 14_u8, 2_u8, 5_u8, 4_u8, 15_u8, 6_u8, 10_u8, 0_u8, 8_u8],
      Slice[9_u8, 5_u8, 2_u8, 10_u8, 0_u8, 7_u8, 4_u8, 15_u8, 14_u8, 11_u8, 6_u8, 3_u8, 1_u8, 12_u8, 8_u8, 13_u8],
      Slice[2_u8, 6_u8, 0_u8, 8_u8, 12_u8, 10_u8, 11_u8, 3_u8, 4_u8, 7_u8, 15_u8, 1_u8, 13_u8, 5_u8, 14_u8, 9_u8],
      Slice[12_u8, 1_u8, 14_u8, 4_u8, 5_u8, 15_u8, 13_u8, 10_u8, 0_u8, 6_u8, 9_u8, 8_u8, 7_u8, 3_u8, 2_u8, 11_u8],
      Slice[13_u8, 7_u8, 12_u8, 3_u8, 11_u8, 14_u8, 1_u8, 9_u8, 5_u8, 15_u8, 8_u8, 2_u8, 0_u8, 4_u8, 6_u8, 10_u8],
      Slice[6_u8, 14_u8, 11_u8, 0_u8, 15_u8, 9_u8, 3_u8, 8_u8, 12_u8, 13_u8, 1_u8, 10_u8, 2_u8, 7_u8, 4_u8, 5_u8],
      Slice[10_u8, 8_u8, 7_u8, 1_u8, 2_u8, 4_u8, 6_u8, 5_u8, 15_u8, 9_u8, 3_u8, 13_u8, 11_u8, 14_u8, 12_u8, 0_u8],
      Slice[0_u8, 2_u8, 4_u8, 6_u8, 1_u8, 3_u8, 5_u8, 7_u8, 8_u8, 10_u8, 12_u8, 14_u8, 9_u8, 11_u8, 13_u8, 15_u8], # equal to the first
      Slice[14_u8, 4_u8, 9_u8, 13_u8, 10_u8, 8_u8, 15_u8, 6_u8, 1_u8, 0_u8, 11_u8, 5_u8, 12_u8, 2_u8, 7_u8, 3_u8], # equal to the second
    ]

    @h : Slice(UInt64)
    @c : Slice(UInt64)
    @size : Int32
    @block : Bytes # Bytes[BLOCK_SIZE]
    @offset : Int32

    @keylen : Int32
    @key : Bytes # Bytes[BLOCK_SIZE]

    def initialize(hash_size : Int32, key : Bytes? = nil)
      if hash_size < 1 || hash_size > SIZE
        raise "Invalid hash size"
      end

      if key && key.size > SIZE
        raise "Invalid key size"
      end

      @size = hash_size
      @keylen = key ? key.size : 0

      @h = Slice(UInt64).new(8)
      @c = Slice(UInt64).new(2)
      @key = Bytes.new(BLOCK_SIZE)
      @block = Bytes.new(BLOCK_SIZE)

      # Reset
      @h = IV.clone
      @h[0] ^= @size | (@keylen.to_u64 << 8) | (1_u32 << 16) | (1_u32 << 24)
      @offset, @c[0], @c[1] = 0, 0_u64, 0_u64
      if @keylen > 0
        @block.copy_from(@key)
        @offset = BLOCK_SIZE
      end
    end

    def self.new512(key = nil)
      new(SIZE, key)
    end

    def self.new384(key = nil)
      new(SIZE384, key)
    end

    def self.new256(key = nil)
      new(SIZE256, key)
    end

    def self.sum512(data)
      sum = Bytes.new(SIZE)
      checksum(sum, SIZE, data)
      sum
    end

    def self.sum384(data)
      sum = Bytes.new(SIZE)
      sum384 = Bytes.new(SIZE384)
      checksum(sum, SIZE384, data)
      sum[...SIZE384].copy_to(sum384)
      sum384
    end

    def self.sum256(data)
      sum = Bytes.new(SIZE)
      sum256 = Bytes.new(SIZE256)
      checksum(sum, SIZE256, data)
      sum[...SIZE256].copy_to(sum256)
      sum256
    end

    def reset
      @h = IV.clone
      @h[0] ^= @size | (@keylen.to_u64 << 8) | (1_u32 << 16) | (1_u32 << 24)
      @offset, @c[0], @c[1] = 0, 0_u64, 0_u64
      if @keylen > 0
        @block = @key
        @offset = BLOCK_SIZE
      end
    end

    # TODO:
    # def marshal_binary
    # end

    # def unmarshal_binary
    # end

    def write(p)
      p = p.to_slice
      n = p.size

      if @offset > 0
        remaining = BLOCK_SIZE - @offset
        if n <= remaining
          p.copy_to(@block[@offset...])
          @offset += @block[@offset...].size
          return
        end

        p[...remaining].copy_to(@block[@offset...])
        self.class.hash_blocks(@h, @c, 0, @block)
        @offset = 0
        p = p[remaining...]
      end

      if (length = p.size.to_u32; length > BLOCK_SIZE)
        nn = length & ~(BLOCK_SIZE - 1)
        if length == nn
          nn -= BLOCK_SIZE
        end
        self.class.hash_blocks(@h, @c, 0, p[...nn])
        p = p[nn...]
      end

      if p.size > 0
        p = p[...@block.size] if p.size > @block.size
        p.copy_to(@block)
        @offset += p.size
      end
    end

    def sum(sum = nil)
      hash = Bytes.new(SIZE)
      final(hash)
      sum ? sum.to_slice + hash[...@size] : hash[...@size]
    end

    private def final(hash)
      block = Bytes.new(BLOCK_SIZE)
      (@block.size > @offset ? @block[...@offset] : @block).copy_to(block)
      remaining = UInt64.new(BLOCK_SIZE - @offset)

      c = @c
      if c[0] < remaining
        c[1] = c[1] &- 1
      end
      c[0] = c[0] &- remaining

      h = @h
      self.class.hash_blocks(h, c, 0xFFFFFFFFFFFFFFFF_u64, block)

      h.each_with_index do |v, i|
        IO::ByteFormat::LittleEndian.encode(v.to_u64, hash[(8 * i)...])
      end

      self
    end

    # :nodoc:
    def self.hash_blocks(h, c, flag, blocks)
      blocks = blocks.to_slice
      flag = flag.to_u64

      m = Slice(UInt64).new(16)
      c0, c1 = c[0], c[1]

      i = 0
      while i < blocks.size
        c0 = c0 &+ BLOCK_SIZE
        if c0 < BLOCK_SIZE
          c1 = c1 &+ 1
        end

        v0, v1, v2, v3, v4, v5, v6, v7 = h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]
        v8, v9, v10, v11, v12, v13, v14, v15 = IV[0], IV[1], IV[2], IV[3], IV[4], IV[5], IV[6], IV[7]
        v12 ^= c0
        v13 ^= c1
        v14 ^= flag

        m.each_index do |j|
          m[j] = i >= blocks.size ? 0_u64 : IO::ByteFormat::LittleEndian.decode(UInt64, blocks[i...])
          i += 8
        end

        SIGMA.each_index do |j|
          s = SIGMA[j]

          v0 = v0 &+ m[s[0]]
          v0 = v0 &+ v4
          v12 ^= v0
          v12 = v12.to_u64.rotate_left(-32)
          v8 = v8 &+ v12
          v4 ^= v8
          v4 = v4.to_u64.rotate_left(-24)
          v1 = v1 &+ m[s[1]]
          v1 = v1 &+ v5
          v13 ^= v1
          v13 = v13.to_u64.rotate_left(-32)
          v9 = v9 &+ v13
          v5 ^= v9
          v5 = v5.to_u64.rotate_left(-24)
          v2 = v2 &+ m[s[2]]
          v2 = v2 &+ v6
          v14 ^= v2
          v14 = v14.to_u64.rotate_left(-32)
          v10 = v10 &+ v14
          v6 ^= v10
          v6 = v6.to_u64.rotate_left(-24)
          v3 = v3 &+ m[s[3]]
          v3 = v3 &+ v7
          v15 ^= v3
          v15 = v15.to_u64.rotate_left(-32)
          v11 = v11 &+ v15
          v7 ^= v11
          v7 = v7.to_u64.rotate_left(-24)

          v0 = v0 &+ m[s[4]]
          v0 = v0 &+ v4
          v12 ^= v0
          v12 = v12.to_u64.rotate_left(-16)
          v8 = v8 &+ v12
          v4 ^= v8
          v4 = v4.to_u64.rotate_left(-63)
          v1 = v1 &+ m[s[5]]
          v1 = v1 &+ v5
          v13 ^= v1
          v13 = v13.to_u64.rotate_left(-16)
          v9 = v9 &+ v13
          v5 ^= v9
          v5 = v5.to_u64.rotate_left(-63)
          v2 = v2 &+ m[s[6]]
          v2 = v2 &+ v6
          v14 ^= v2
          v14 = v14.to_u64.rotate_left(-16)
          v10 = v10 &+ v14
          v6 ^= v10
          v6 = v6.to_u64.rotate_left(-63)
          v3 = v3 &+ m[s[7]]
          v3 = v3 &+ v7
          v15 ^= v3
          v15 = v15.to_u64.rotate_left(-16)
          v11 = v11 &+ v15
          v7 ^= v11
          v7 = v7.to_u64.rotate_left(-63)

          v0 = v0 &+ m[s[8]]
          v0 = v0 &+ v5
          v15 ^= v0
          v15 = v15.to_u64.rotate_left(-32)
          v10 = v10 &+ v15
          v5 ^= v10
          v5 = v5.to_u64.rotate_left(-24)
          v1 = v1 &+ m[s[9]]
          v1 = v1 &+ v6
          v12 ^= v1
          v12 = v12.to_u64.rotate_left(-32)
          v11 = v11 &+ v12
          v6 ^= v11
          v6 = v6.to_u64.rotate_left(-24)
          v2 = v2 &+ m[s[10]]
          v2 = v2 &+ v7
          v13 ^= v2
          v13 = v13.to_u64.rotate_left(-32)
          v8 = v8 &+ v13
          v7 ^= v8
          v7 = v7.to_u64.rotate_left(-24)
          v3 = v3 &+ m[s[11]]
          v3 = v3 &+ v4
          v14 ^= v3
          v14 = v14.to_u64.rotate_left(-32)
          v9 = v9 &+ v14
          v4 ^= v9
          v4 = v4.to_u64.rotate_left(-24)

          v0 = v0 &+ m[s[12]]
          v0 = v0 &+ v5
          v15 ^= v0
          v15 = v15.to_u64.rotate_left(-16)
          v10 = v10 &+ v15
          v5 ^= v10
          v5 = v5.to_u64.rotate_left(-63)
          v1 = v1 &+ m[s[13]]
          v1 = v1 &+ v6
          v12 ^= v1
          v12 = v12.to_u64.rotate_left(-16)
          v11 = v11 &+ v12
          v6 ^= v11
          v6 = v6.to_u64.rotate_left(-63)
          v2 = v2 &+ m[s[14]]
          v2 = v2 &+ v7
          v13 ^= v2
          v13 = v13.to_u64.rotate_left(-16)
          v8 = v8 &+ v13
          v7 ^= v8
          v7 = v7.to_u64.rotate_left(-63)
          v3 = v3 &+ m[s[15]]
          v3 = v3 &+ v4
          v14 ^= v3
          v14 = v14.to_u64.rotate_left(-16)
          v9 = v9 &+ v14
          v4 ^= v9
          v4 = v4.to_u64.rotate_left(-63)
        end

        h[0] ^= v0 ^ v8
        h[1] ^= v1 ^ v9
        h[2] ^= v2 ^ v10
        h[3] ^= v3 ^ v11
        h[4] ^= v4 ^ v12
        h[5] ^= v5 ^ v13
        h[6] ^= v6 ^ v14
        h[7] ^= v7 ^ v15
      end

      c[0], c[1] = c0, c1
    end

    # :nodoc:
    def self.checksum(sum, hash_size, data)
      h = IV.dup
      h[0] ^= hash_size.to_u64 | (1_u32 << 16) | (1_u32 << 24)
      c = Slice(UInt64).new(2)

      if (length = data.size) && length > BLOCK_SIZE
        n = length & ~(BLOCK_SIZE - 1)
        if length == n
          n -= BLOCK_SIZE
        end
        self.hash_blocks(h, c, 0, data[...n])
        data = data[n...]
      end

      block = Bytes.new(BLOCK_SIZE)
      data.copy_to(block)

      remaining = UInt64.new(BLOCK_SIZE - data.size)
      if c[0] < remaining
        c[1] = c[1] &- 1
      end
      c[0] = c[0] &- remaining

      hash_blocks(h, c, 0xFFFFFFFFFFFFFFFF_u64, block)

      h[...((hash_size + 7) // 8)].each_with_index do |v, i|
        IO::ByteFormat::LittleEndian.encode(v.to_u64, sum[(8 * i)...])
      end
    end
  end
end
