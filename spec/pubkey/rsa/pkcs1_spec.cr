require "../../spec_helper"

describe Crypto::RSA::PKCS1 do
  context "Crypto::RSA::PKCS1.i2osp" do
    it "raises an error if x >= 256**len" do
      expect_raises(ArgumentError) do
        Crypto::RSA::PKCS1.i2osp(256**3, 2)
      end

      expect_raises(ArgumentError) do
        Crypto::RSA::PKCS1.i2osp(9_202_000, 2)
      end
    end

    it "returns the correct octet string" do
      Crypto::RSA::PKCS1.i2osp(9_202_000, 3).should eq(Bytes[140, 105, 80])
    end

    it "inserts leading zeroes as needed" do
      Crypto::RSA::PKCS1.i2osp(9_202_000, 4).should eq(Bytes[0, 140, 105, 80])
      Crypto::RSA::PKCS1.i2osp(9_202_000, 5).should eq(Bytes[0, 0, 140, 105, 80])
    end

    it "encodes zero correctly" do
      Crypto::RSA::PKCS1.i2osp(0, 1).should eq(Bytes[0])
    end
  end

  context "Crypto::RSA::PKCS1.os2ip" do
    it "returns the correct integer value" do
      Crypto::RSA::PKCS1.os2ip(Bytes[0]).should eq(0)
      Crypto::RSA::PKCS1.os2ip(Bytes[140, 105, 80]).should eq(9_202_000)
    end

    it "decodes zero correctly" do
      Crypto::RSA::PKCS1.os2ip(Bytes[0]).should eq(0)
    end
  end

  context "Crypto::RSA::PKCS1.rsaep" do
    it "raises an error if m is out of range" do
      expect_raises(ArgumentError) do
        Crypto::RSA::PKCS1.rsaep([0, 0], 1)
      end
    end

    # @see http://en.wikipedia.org/wiki/Crypto::RSA#A_worked_example
    it "encrypts the Wikipedia example correctly" do
      Crypto::RSA::PKCS1.rsaep([n = 3233, e = 17], m = 'A'.ord).should eq(2790)
    end
  end

  context "Crypto::RSA::PKCS1.rsadp" do
    it "raises an error if c is out of range" do
      expect_raises(ArgumentError) do
        Crypto::RSA::PKCS1.rsadp([0, 0], 1)
      end
    end

    # @see http://en.wikipedia.org/wiki/Crypto::RSA#A_worked_example
    it "decrypts the Wikipedia example correctly" do
      Crypto::RSA::PKCS1.rsadp([n = 3233, d = 2753], c = 2790).should eq('A'.ord)
    end
  end

  context "Crypto::RSA::PKCS1.rsasp1" do
    it "raises an error if m is out of range" do
      expect_raises(ArgumentError) do
        Crypto::RSA::PKCS1.rsasp1([0, 0], 1)
      end
    end

    # TODO
  end

  context "Crypto::RSA::PKCS1.rsavp1" do
    it "raises an error if s is out of range" do
      expect_raises(ArgumentError) do
        Crypto::RSA::PKCS1.rsavp1([0, 0], 1)
      end
    end

    # TODO
  end
end
