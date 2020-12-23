require "../spec_helper"

describe Crypto::IGE do
  describe "exceptions" do
    it "should raise if the data is empty" do
      expect_raises(Exception, "data must not be empty") do
        Crypto::IGE.encrypt(Bytes.new(0), RANDOM.random_bytes(32), RANDOM.random_bytes(32))
      end
    end

    it "should raise if the data size is not a multiple of 16" do
      expect_raises(Exception, "data byte size must be a multiple of 16") do
        Crypto::IGE.encrypt(RANDOM.random_bytes(12), RANDOM.random_bytes(32), RANDOM.random_bytes(32))
      end
    end

    it "should raise if the key size is not 32 bytes" do
      expect_raises(Exception, "key byte size must be 32 bytes exactly") do
        Crypto::IGE.encrypt(RANDOM.random_bytes(16), RANDOM.random_bytes(31), RANDOM.random_bytes(32))
      end
    end

    it "should raise if the iv size is not 32 bytes" do
      expect_raises(Exception, "iv byte size must be 32 bytes exactly") do
        Crypto::IGE.encrypt(RANDOM.random_bytes(16), RANDOM.random_bytes(32), RANDOM.random_bytes(31))
      end
    end
  end
end
