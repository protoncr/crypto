require "./prime"

module TGCrypto
  module Math
    extend ::Math

    class ArithmeticError < ArgumentError; end

    # Returns the Bezout coefficients of the two nonzero integers `a` and
    # `b` using the extended Euclidean algorithm.
    #
    # Example
    # ```
    # TGCrypto::Math.egcd(120, 23)    #=> [-9, 47]
    # TGCrypto::Math.egcd(421, 111)   #=> [-29, 110]
    # TGCrypto::Math.egcd(93, 219)    #=> [33, -14]
    # TGCrypto::Math.egcd(4864, 3458) #=> [32, -45]
    # ```
    #
    def self.egcd(a, b)
      if a.modulo(b).zero?
        {0, 1}
      else
        x, y = self.egcd(b, a.modulo(b))
        {y, x - y * a.div(b)}
      end
    end

    # Returns the modular multiplicative inverse of the integer `b` modulo
    # `m`, where `b <= m`.
    #
    # The running time of the used algorithm, the extended Euclidean
    # algorithm, is on the order of O(log2 _m_).
    #
    # Example
    # ```
    #   TGCrypto::Math.modinv(3, 11)  #=> 4
    #   TGCrypto::Math.modinv(6, 35)  #=> 6
    #   TGCrypto::Math.modinv(-6, 35) #=> 29
    #   TGCrypto::Math.modinv(6, 36)  #=> ArithmeticError
    #
    def self.modinv(b, m)
      if m > 0 && coprime?(b, m)
        egcd(b, m).first.modulo(m)
      else
        raise ArithmeticError.new("modulus #{m} is not positive") if m <= 0
        raise ArithmeticError.new("#{b} is not coprime to #{m}")
      end
    end

    # Performs modular exponentiation in a memory-efficient manner.
    #
    # This is equivalent to `base**exponent % modulus` but much faster for
    # large exponents.
    #
    # The running time of the used algorithm, the right-to-left binary
    # method, is on the order of O(log _exponent_).
    #
    # Example
    # ```
    # TGCrypto::Math.modpow(5, 3, 13)   #=> 8
    # TGCrypto::Math.modpow(4, 13, 497) #=> 445
    # ```
    #
    def self.modpow(base, exponent, modulus)
      result = 1
      while exponent > 0
        result   = (base * result) % modulus unless (exponent & 1).zero?
        base     = (base * base)   % modulus
        exponent >>= 1
      end
      result
    end

    # Returns the Euler totient for the positive integer `n`.
    #
    # Example
    # ```
    # (1..5).map { |n| RSA::Math.phi(n) } #=> [1, 1, 2, 2, 4]
    # ```
    #
    def self.phi(n)
      case
      when n < 0     then raise ArgumentError.new("expected a positive integer, but got #{n}")
      when n < 2     then 1 # by convention
      when Prime.prime?(n) then n - 1
      else Prime.factorize(n).reduce(n) { |product, (p, e)| product * (ONE - (ONE / BigDecimal.new(p.to_s))) }.round.to_i
      end
    end

    # Returns the base-256 logarithm of `n`.
    #
    # Example
    # ```
    # RSA::Math.log256(16)   #=> 0.5
    # RSA::Math.log256(1024) #=> 1.25
    # ```
    #
    def self.log256(n)
      ::Math.log(n, 256)
    end

    # Euclid's extended algorithm for finding the multiplicative inverse of two numbers
    def self.mod_inverse(e, phi)
      d_int = 0_i64
      i = 1_i64

      stop = false
      until stop
        temp1 = phi * i + 1
        d = temp1 / e
        d_int = d.to_i
        i += 1
        if d_int == d
          stop = true
        end
      end

      return d_int
    end
  end
end

