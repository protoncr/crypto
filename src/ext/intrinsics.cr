# lib LibIntrinsics
#   fun fshl8 = "llvm.fshl.i8"(a : Int8, b : Int8, c : Int8) : Int8
#   fun fshl16 = "llvm.fshl.i16"(a : Int16, b : Int16, c : Int16) : Int16
#   fun fshl32 = "llvm.fshl.i32"(a : Int32, b : Int32, c : Int32) : Int32
#   fun fshl64 = "llvm.fshl.i64"(a : Int64, b : Int64, c : Int64) : Int64
#   fun fshl128 = "llvm.fshl.i128"(a : Int128, b : Int128, c : Int128) : Int128

#   fun fshr8 = "llvm.fshr.i8"(a : Int8, b : Int8, c : Int8) : Int8
#   fun fshr16 = "llvm.fshr.i16"(a : Int16, b : Int16, c : Int16) : Int16
#   fun fshr32 = "llvm.fshr.i32"(a : Int32, b : Int32, c : Int32) : Int32
#   fun fshr64 = "llvm.fshr.i64"(a : Int64, b : Int64, c : Int64) : Int64
#   fun fshr128 = "llvm.fshr.i128"(a : Int128, b : Int128, c : Int128) : Int128
# end

# module Intrinsics
#   def self.funnel_shift_left8(msb, ob, amt)
#     LibIntrinsics.fshl8(msb, ob, amt)
#   end

#   def self.funnel_shift_left16(msb, ob, amt)
#     LibIntrinsics.fshl16(msb, ob, amt)
#   end

#   def self.funnel_shift_left32(msb, ob, amt)
#     LibIntrinsics.fshl32(msb, ob, amt)
#   end

#   def self.funnel_shift_left64(msb, ob, amt)
#     LibIntrinsics.fshl64(msb, ob, amt)
#   end

#   def self.funnel_shift_left128(msb, ob, amt)
#     LibIntrinsics.fshl128(msb, ob, amt)
#   end

#   def self.funnel_shift_right8(msb, ob, amt)
#     LibIntrinsics.fshr8(msb, ob, amt)
#   end

#   def self.funnel_shift_right16(msb, ob, amt)
#     LibIntrinsics.fshr16(msb, ob, amt)
#   end

#   def self.funnel_shift_right32(msb, ob, amt)
#     LibIntrinsics.fshr32(msb, ob, amt)
#   end

#   def self.funnel_shift_right64(msb, ob, amt)
#     LibIntrinsics.fshr64(msb, ob, amt)
#   end

#   def self.funnel_shift_right128(msb, ob, amt)
#     LibIntrinsics.fshr128(msb, ob, amt)
#   end
# end
