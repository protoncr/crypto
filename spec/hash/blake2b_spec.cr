require "../spec_helper"
require "./blake_mocks"

describe Crypto::Blake2b do
  it "has the correct output size" do
    input = Bytes.new(256)

    BLAKE2B_KAT_OUT_SIZE.size.times do |i|
      out_size = i + 1
      h = Crypto::Blake2b.new(out_size)
      h.write(input)
      output = h.sum
      output[0...out_size].should eq(BLAKE2B_KAT_OUT_SIZE[i])
    end
  end

  it "works with known vectors" do
    input = Bytes.new(256)
    input.size.times do |i|
      input[i] = i.to_u8
    end

    BLAKE2B_KAT.size.times do |i|
      h = Crypto::Blake2b.new(Crypto::Blake2b::SIZE)
      h.write(input[0...i])
      output = h.sum

      output.should eq(BLAKE2B_KAT[i])
    end
  end

  it "works with known keyed vectors" do
    input = Bytes.new(256)
    key = Bytes.new(Crypto::Blake2b::SIZE)

    input.size.times do |i|
      input[i] = i.to_u8
    end

    key.size.times do |i|
      key[i] = i.to_u8
    end

    BLAKE2B_KEYED_KAT.size.times do |i|
      h = Crypto::Blake2b.new(Crypto::Blake2b::SIZE, key)
      h.write(input[0...i])
      output = h.sum
      output.should eq(BLAKE2B_KEYED_KAT[i])
    end
  end
end
