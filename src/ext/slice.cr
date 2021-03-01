struct Slice(T)
  def self.concat(*others : self)
    total_size = others.map(&.size).sum
    slice = self.new(total_size)
    ptr = slice.to_unsafe
    others.each_with_index do |s, i|
      s.copy_to(ptr, s.size)
      ptr += s.size
    end
    slice
  end

  def +(other : self)
    self.class.concat(self, other)
  end

  def clear
    each_index do |i|
      self[i] = T.new(0)
    end
    self
  end
end
