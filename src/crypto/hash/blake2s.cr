module Crypto
  class Blake2s
    BLOCK_BYTES = 64
    KEY_BYTES   = 32
    OUT_BYTES   = 32
    BUF_BYTES   = 64 * 2

    IV = StaticArray[
      0x6a09e667_u32, 0xbb67ae85_u32, 0x3c6ef372_u32, 0xa54ff53a_u32,
      0x510e527f_u32, 0x9b05688c_u32, 0x1f83d9ab_u32, 0x5be0cd19_u32,
    ]

    SIGMA = StaticArray[
      StaticArray[0_u8, 1_u8, 2_u8, 3_u8, 4_u8, 5_u8, 6_u8, 7_u8, 8_u8, 9_u8, 10_u8, 11_u8, 12_u8, 13_u8, 14_u8, 15_u8],
      StaticArray[14_u8, 10_u8, 4_u8, 8_u8, 9_u8, 15_u8, 13_u8, 6_u8, 1_u8, 12_u8, 0_u8, 2_u8, 11_u8, 7_u8, 5_u8, 3_u8],
      StaticArray[11_u8, 8_u8, 12_u8, 0_u8, 5_u8, 2_u8, 15_u8, 13_u8, 10_u8, 14_u8, 3_u8, 6_u8, 7_u8, 1_u8, 9_u8, 4_u8],
      StaticArray[7_u8, 9_u8, 3_u8, 1_u8, 13_u8, 12_u8, 11_u8, 14_u8, 2_u8, 6_u8, 5_u8, 10_u8, 4_u8, 0_u8, 15_u8, 8_u8],
      StaticArray[9_u8, 0_u8, 5_u8, 7_u8, 2_u8, 4_u8, 10_u8, 15_u8, 14_u8, 1_u8, 11_u8, 12_u8, 6_u8, 8_u8, 3_u8, 13_u8],
      StaticArray[2_u8, 12_u8, 6_u8, 10_u8, 0_u8, 11_u8, 8_u8, 3_u8, 4_u8, 13_u8, 7_u8, 5_u8, 15_u8, 14_u8, 1_u8, 9_u8],
      StaticArray[12_u8, 5_u8, 1_u8, 15_u8, 14_u8, 13_u8, 4_u8, 10_u8, 0_u8, 7_u8, 6_u8, 3_u8, 9_u8, 2_u8, 8_u8, 11_u8],
      StaticArray[13_u8, 11_u8, 7_u8, 14_u8, 12_u8, 1_u8, 3_u8, 9_u8, 5_u8, 0_u8, 15_u8, 4_u8, 8_u8, 6_u8, 2_u8, 10_u8],
      StaticArray[6_u8, 15_u8, 14_u8, 9_u8, 11_u8, 3_u8, 0_u8, 8_u8, 12_u8, 2_u8, 13_u8, 7_u8, 1_u8, 4_u8, 10_u8, 5_u8],
      StaticArray[10_u8, 2_u8, 8_u8, 4_u8, 7_u8, 6_u8, 1_u8, 5_u8, 15_u8, 11_u8, 9_u8, 14_u8, 3_u8, 12_u8, 13_u8, 0_u8],
    ]

    @size : Int32
    @h : StaticArray(UInt32, 8)
    @t : StaticArray(UInt32, 2)
    @f : StaticArray(UInt32, 2)
    @buf : Bytes
    @buf_len : UInt32

    def initialize(size, key = nil)
      param = encode_params(size.to_u8, key ? key.size : 0)
      state = IV.dup

      (0...state.size).each do |i|
        state[i] ^= Blake2s.load32(param[(i * 4)..])
      end

      @size = size
      @h = state
      @t = StaticArray[0_u32, 0_u32]
      @f = StaticArray[0_u32, 0_u32]
      @buf = Bytes.new(BUF_BYTES)
      @buf_len = 0

      if key
        key = key.to_slice
        block = Bytes.new(BLOCK_BYTES)
        key.copy_to(block.to_slice)
        self.update(block)
      end
    end

    def update(m)
      m = m.to_slice

      while m.size > 0
        left = @buf_len
        fill = 2 * BLOCK_BYTES - left

        if m.size > fill
          (0...fill).each do |i|
            @buf[left + i] = m[i]
          end

          @buf_len += fill
          m = m[fill..]
          self.increment_counter(BLOCK_BYTES)
          self.compress
          (0...BLOCK_BYTES).each do |i|
            @buf[i] = @buf[i + BLOCK_BYTES]
          end
          @buf_len -= BLOCK_BYTES
        else
          (0...m.size).each do |i|
            @buf[left + i] = m[i]
          end
          @buf_len += m.size
          m = m[m.size..]
        end
      end

      self
    end

    def digest(output : Bytes? = nil)
      output = output ? output.to_slice : Bytes.new(@size)
      buf = StaticArray(UInt8, OUT_BYTES).new(0_u8)

      if @buf_len > BLOCK_BYTES
        self.increment_counter(BLOCK_BYTES)
        self.compress
        BLOCK_BYTES.times do |i|
          @buf[i] = @buf[i + BLOCK_BYTES]
        end
        @buf_len -= BLOCK_BYTES
      end

      n = @buf_len.to_u32
      self.increment_counter(n)
      @f[0] = ~0_u32
      (@buf_len...@buf.size).each do |i|
        @buf[i] = 0
      end

      self.compress
      (0...@h.size).each do |i|
        Blake2s.store32(buf[(i * 4)..], @h[i])
      end

      (0...Math.min(output.size, OUT_BYTES)).each do |i|
        output[i] = buf[i]
      end

      output
    end

    def increment_counter(inc)
      inc = inc.to_u32
      @t[0] += inc
      @t[1] += (@t[0] < inc) ? 1 : 0
    end

    def compress
      m = StaticArray(UInt32, 16).new(0)
      v = StaticArray(UInt32, 16).new(0)
      block = @buf

      (0...m.size).each do |i|
        m[i] = Blake2s.load32(block[(i * 4)..])
      end

      8.times do |i|
        v[i] = @h[i]
      end

      v[8] = IV[0]
      v[9] = IV[1]
      v[10] = IV[2]
      v[11] = IV[3]
      v[12] = @t[0] ^ IV[4]
      v[13] = @t[1] ^ IV[5]
      v[14] = @f[0] ^ IV[6]
      v[15] = @f[1] ^ IV[7]

      10.times do |i|
        g(i, 0, v[0], v[4], v[8], v[12])
        g(i, 1, v[1], v[5], v[9], v[13])
        g(i, 2, v[2], v[6], v[10], v[14])
        g(i, 3, v[3], v[7], v[11], v[15])
        g(i, 4, v[0], v[5], v[10], v[15])
        g(i, 5, v[1], v[6], v[11], v[12])
        g(i, 6, v[2], v[7], v[8], v[13])
        g(i, 7, v[3], v[4], v[9], v[14])
      end

      8.times do |i|
        @h[i] = @h[i] ^ v[i] ^ v[i + 8]
      end
    end

    def self.checksum(size, data, key = nil, output = nil)
      hasher = Blake2s.new(size // 8, key)
      hasher.update(data)
      hasher.digest(output)
    end

    private def encode_params(size, keylen)
      param = StaticArray(UInt8, 64).new(0_u8)
      param[0] = size.to_u8
      param[1] = keylen.to_u8
      param[2] = 1 # fanout
      param[3] = 1 # depth
      param
    end

    # :nodoc:
    def self.load32(b)
      IO::ByteFormat::LittleEndian.decode(UInt32, b)
    end

    # :nodoc:
    def self.store32(b, v)
      IO::ByteFormat::LittleEndian.encode(v.to_u32, b)
    end

    macro g(r, i, a, b, c, d)
      {{ a.id }} = {{ a.id }} &+ ({{ b.id }}) &+ (m[SIGMA[{{ r.id }}][2*{{ i.id }}+0].to_u32])
      {{ d.id }} = ({{ d.id }} ^ {{ a.id }}).rotate_right(16)
      {{ c.id }} = {{ c.id }} &+ ({{ d.id }})
      {{ b.id }} = ({{ b.id }} ^ {{ c.id }}).rotate_right(12)
      {{ a.id }} = {{ a.id }} &+ ({{ b.id }}) &+ (m[SIGMA[{{ r.id }}][2*{{ i.id }}+1].to_u32])
      {{ d.id }} = ({{ d.id }} ^ {{ a.id }}).rotate_right(8)
      {{ c.id }} = {{ c.id }} &+ ({{ d.id }})
      {{ b.id }} = ({{ b.id }} ^ {{ c.id }}).rotate_right(7)
    end
  end
end
