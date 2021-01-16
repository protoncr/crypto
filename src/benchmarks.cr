require "benchmark"

require "./crypto"

module Crypto
  module Benchmarks
    def self.run_all
      puts "Blake2b"
      self.blake2b
    end

    def self.blake2b
      h = Crypto::Blake2b.new(Crypto::Blake2b::OUT_BYTES)
      buf = Random.new.random_bytes(8 << 10)
      Benchmark.bm do |x|
        x.report("write 1k") do
          100000.times { h.update(buf[0...1024]) }
        end

        x.report("write 8k") do
          100000.times { h.update(buf) }
        end

        x.report("hash 64") do
          100000.times { Crypto::Blake2b.checksum(512, buf[0...64]) }
        end

        x.report("hash 128") do
          100000.times { Crypto::Blake2b.checksum(512, buf[0...128]) }
        end

        x.report("hash 1k") do
          100000.times { Crypto::Blake2b.checksum(512, buf[0...1024]) }
        end

        x.report("hash 8k") do
          100000.times { Crypto::Blake2b.checksum(512, buf) }
        end
      end
    end
  end
end

Crypto::Benchmarks.run_all
