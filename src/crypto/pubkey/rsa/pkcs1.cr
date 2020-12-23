module Crypto
  module RSA
    # Support for the PKCS #1 (aka RFC 3447) padding schemes.
    #
    module PKCS1
      # Converts a nonnegative integer into an octet string of a specified
      # length.
      #
      # This is the PKCS #1 I2OSP (Integer-to-Octet-String) primitive.
      # Refer to PKCS #1 v2.1 pp. 8-9, section 4.1.
      #
      # Example
      # ```
      # RSA::PKCS1.i2osp(9_202_000, 2)    #=> ArgumentError: integer too large
      # RSA::PKCS1.i2osp(9_202_000, 3)    #=> "\x8C\x69\x50"
      # RSA::PKCS1.i2osp(9_202_000, 4)    #=> "\x00\x8C\x69\x50"
      # ```
      #
      def self.i2osp(x, len = nil)
        raise ArgumentError.new("integer too large") if len && x >= 256_i64 ** len

        a = Array(UInt8).new
        while x > 0
          b = x & 0xFF
          x >>= 8
          a << b.to_u8
        end

        a.reverse!
        if len
          while a.size != len
            a.unshift(0x00_u8)
          end
        end

        Slice.new(a.to_unsafe, a.size)
      end

      # Converts an octet string into a nonnegative integer.
      #
      # This is the PKCS #1 OS2IP (Octet-String-to-Integer) primitive.
      # Refer to PKCS #1 v2.1 p. 9, section 4.2.
      #
      # Example
      # ```
      # RSA::PKCS1.os2ip("\x8C\x69\x50")  #=> 9_202_000
      # ```
      #
      def self.os2ip(x)
        x = x.is_a?(String) ? x.bytes : x.to_a
        x.reduce(0_u64) { |n, b| (n << 8) + b }
      end

      # Produces a ciphertext representative from a message representative
      # under the control of a public key.
      #
      # This is the PKCS #1 RSAEP encryption primitive.
      # Refer to PKCS #1 v2.1 p. 10, section 5.1.1.
      #
      def self.rsaep(k, m)
        n, e = k.to_a
        raise ArgumentError.new("message representative out of range") unless m >= 0 && m < n
        Math.modpow(m, e, n)
      end

      # Recovers the message representative from a ciphertext representative
      # under the control of a private key.
      #
      # This is the PKCS #1 RSADP decryption primitive.
      # Refer to PKCS #1 v2.1 pp. 10-11, section 5.1.2.
      #
      def self.rsadp(k, c)
        n, d = k.to_a
        raise ArgumentError.new("ciphertext representative out of range") unless c >= 0 && c < n
        Math.modpow(c, d, n)
      end

      # Produces a signature representative from a message representative
      # under the control of a private key.
      #
      # This is the PKCS #1 RSASP1 signature primitive.
      # Refer to PKCS #1 v2.1 pp. 12-13, section 5.2.1.
      #
      def self.rsasp1(k, m)
        n, d = k.to_a
        raise ArgumentError.new("message representative out of range") unless m >= 0 && m < n
        Math.modpow(m, d, n)
      end

      # Recovers the message representative from a signature representative
      # under the control of a public key.
      #
      # This is the PKCS #1 RSAVP1 verification primitive.
      # Refer to PKCS #1 v2.1 p. 13, section 5.2.2.
      #
      def self.rsavp1(k, s)
        n, e = k.to_a
        raise ArgumentError.new("signature representative out of range") unless s >= 0 && s < n
        Math.modpow(s, e, n)
      end
    end
  end
end
