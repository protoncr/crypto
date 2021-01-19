require "benchmark"

require "./crypto"

module Crypto
  module Benchmarks
    def self.run_all
      puts "Blake2b"
      self.blake2b
    end

    def self.blake2b
      h = Crypto::Blake2b.new512
      buf = Random.new.random_bytes(8 << 10)
      Benchmark.ips do |x|
        x.report(label: "write 1k") do
          100000.times { h.write(buf[0...1024]) }
        end

        x.report(label: "write 8k") do
          100000.times { h.write(buf) }
        end

        x.report(label: " hash 64") do
          100000.times { Crypto::Blake2b.sum512(buf[0...64]) }
        end

        x.report(label: "hash 128") do
          100000.times { Crypto::Blake2b.sum512(buf[0...128]) }
        end

        x.report(label: " hash 1k") do
          100000.times { Crypto::Blake2b.sum512(buf[0...1024]) }
        end

        x.report(label: " hash 8k") do
          100000.times { Crypto::Blake2b.sum512(buf) }
        end
      end
    end
  end
end

Crypto::Benchmarks.run_all
