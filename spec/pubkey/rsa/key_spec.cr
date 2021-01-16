require "../../spec_helper"

public_key = Crypto::RSA::PublicKey.new(n = 3233, e = 17)
private_key = Crypto::RSA::PrivateKey.new(n, e, d = 2753, p = 6629676349677357307, q = 1761705206514555017)
key_pair = Crypto::RSA::KeyPair.new(private_key, public_key)

describe Crypto::RSA::Key do
  describe "#private_key" do
    it "returns a key" do
      key_pair.private_key.should be_a(Crypto::RSA::PrivateKey)
    end

    it "returns the private key" do
      key_pair.private_key.should eq(private_key)
    end
  end

  # describe "#private_key?" do
  #   it "returns true" do
  #     key_pair.should be_private_key
  #   end
  # end

  describe "#public_key" do
    it "returns a key" do
      key_pair.public_key.should be_a(Crypto::RSA::PublicKey)
    end

    it "returns the public key" do
      key_pair.public_key.should eq(public_key)
    end
  end

  # describe "#public_key?" do
  #   it "returns true" do
  #     key_pair.should be_public_key
  #   end
  # end

  describe "#valid?" do
    # TODO
  end

  describe "#bytesize" do
    it "returns an integer" do
      key_pair.bytesize.should be_a(Int32)
    end
  end

  describe "#bitsize" do
    it "returns an integer" do
      key_pair.bitsize.should be_a(Int32)
    end
  end

  describe "#modulus" do
    it "returns an integer" do
      key_pair.modulus.should be_a(BigInt)
    end
  end

  # describe "#to_hash" do
  #   it "returns a hash" do
  #     key_pair.to_hash.should be_a(Hash)
  #   end

  #   it "returns a hash with the correct keys" do
  #     [:n, :d, :e].each { |key| key_pair.to_hash.should have_key(key) }
  #   end

  #   it "returns a hash with the correct values" do
  #     key_pair.to_hash.should == {:n => n, :d => d, :e => e}
  #   end
  # end

  describe "#encrypt(Int)" do
    it "returns an integer" do
      key_pair.encrypt(42).should be_a(BigInt)
    end
  end

  describe "#encrypt(String)" do
    it "returns a slice" do
      key_pair.encrypt(42.chr.to_s).should be_a(Bytes)
    end
  end

  describe "#decrypt(Int)" do
    it "returns an integer" do
      key_pair.decrypt(2557).should be_a(BigInt)
    end
  end

  describe "#decrypt(String)" do
    it "returns a slice" do
      key_pair.decrypt(Crypto::RSA::PKCS1.i2osp(2557)).should be_a(Bytes)
    end
  end

  describe "#sign(Integer)" do
    it "returns an integer" do
      key_pair.sign(42).should be_a(BigInt)
    end
  end

  describe "#sign(String)" do
    it "returns a slice" do
      key_pair.sign(42.chr.to_s).should be_a(Bytes)
    end
  end

  describe "#verify(Integer)" do
    it "returns a boolean" do
      key_pair.verify(3065, 42).should be_true
    end
  end

  describe "#verify(String)" do
    it "returns a boolean" do
      key_pair.verify(Crypto::RSA::PKCS1.i2osp(3065), 42.chr.to_s).should be_true
    end
  end
end
