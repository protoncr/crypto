struct StaticArray(T, N)
  def [](range : Range)
    self.to_slice[range]
  end
end
