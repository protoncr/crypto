# require "../spec_helper"
# require "./blake_mocks"

# describe Crypto::Blake2s do
#   it "has the correct output size" do
#     input = Bytes.new(256)

#     BLAKE2S_KAT_OUT_SIZE.size.times do |i|
#       out_size = i + 1
#       output = Bytes.new(Crypto::Blake2s::OUT_BYTES)
#       h = Crypto::Blake2s.new(out_size)
#       h.update(input)
#       h.digest(output)
#       output[0...out_size].should eq(BLAKE2S_KAT_OUT_SIZE[i])
#     end
#   end

#   it "works with known vectors" do
#     input = Bytes.new(256)
#     input.size.times do |i|
#       input[i] = i.to_u8
#     end

#     BLAKE2S_KAT.size.times do |i|
#       output = Bytes.new(Crypto::Blake2s::OUT_BYTES)
#       h = Crypto::Blake2s.new(Crypto::Blake2s::OUT_BYTES)
#       h.update(input[0...i])
#       h.digest(output)

#       output.should eq(BLAKE2S_KAT[i])
#     end
#   end

#   it "works with known keyed vectors" do
#     input = Bytes.new(256)
#     key = Bytes.new(Crypto::Blake2s::KEY_BYTES)

#     input.size.times do |i|
#       input[i] = i.to_u8
#     end

#     key.size.times do |i|
#       key[i] = i.to_u8
#     end

#     BLAKE2S_KEYED_KAT.size.times do |i|
#       output = Bytes.new(Crypto::Blake2s::OUT_BYTES)
#       h = Crypto::Blake2s.new(Crypto::Blake2s::OUT_BYTES, key)
#       h.update(input[0...i])
#       h.digest(output)

#       output.should eq(BLAKE2S_KEYED_KAT[i])
#     end
#   end
# end
