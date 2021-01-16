require "./intrinsics"

struct Int
  abstract def rotate_left(n)
  abstract def rotate_right(n)
end

struct Int8
  def rotate_left(n)
    (self << (n % 8)) | (self >> ((8 - (n % 8)) % 8))
  end

  def rotate_right(n)
    (self >> (n % 8)) | (self << ((8 - (n % 8)) % 8))
  end
end

struct Int16
  def rotate_left(n)
    (self << (n % 16)) | (self >> ((16 - (n % 16)) % 16))
  end

  def rotate_right(n)
    (self >> (n % 16)) | (self << ((16 - (n % 16)) % 16))
  end
end

struct Int32
  def rotate_left(n)
    (self << (n % 32)) | (self >> ((32 - (n % 32)) % 32))
  end

  def rotate_right(n)
    (self >> (n % 32)) | (self << ((32 - (n % 32)) % 32))
  end
end

struct Int64
  def rotate_left(n)
    (self << (n % 64)) | (self >> ((64 - (n % 64)) % 64))
  end

  def rotate_right(n)
    (self >> (n % 64)) | (self << ((64 - (n % 64)) % 64))
  end
end

struct Int128
  def rotate_left(n)
    (self << (n % 128)) | (self >> ((128 - (n % 128)) % 128))
  end

  def rotate_right(n)
    (self >> (n % 128)) | (self << ((128 - (n % 128)) % 128))
  end
end

struct UInt8
  def rotate_left(n)
    (self << (n % 8)) | (self >> ((8 - (n % 8)) % 8))
  end

  def rotate_right(n)
    (self >> (n % 8)) | (self << ((8 - (n % 8)) % 8))
  end
end

struct UInt16
  def rotate_left(n)
    (self << (n % 16)) | (self >> ((16 - (n % 16)) % 16))
  end

  def rotate_right(n)
    (self >> (n % 16)) | (self << ((16 - (n % 16)) % 16))
  end
end

struct UInt32
  def rotate_left(n)
    (self << (n % 32)) | (self >> ((32 - (n % 32)) % 32))
  end

  def rotate_right(n)
    (self >> (n % 32)) | (self << ((32 - (n % 32)) % 32))
  end
end

struct UInt64
  def rotate_left(n)
    (self << (n % 64)) | (self >> ((64 - (n % 64)) % 64))
  end

  def rotate_right(n)
    (self >> (n % 64)) | (self << ((64 - (n % 64)) % 64))
  end
end

struct UInt128
  def rotate_left(n)
    (self << (n % 128)) | (self >> ((128 - (n % 128)) % 128))
  end

  def rotate_right(n)
    (self >> (n % 128)) | (self << ((128 - (n % 128)) % 128))
  end
end

struct BigInt < Int
  def rotate_left(n)
    raise NotImplementedError.new("rotate_left")
  end

  def rotate_right(n)
    raise NotImplementedError.new("rotate_right")
  end
end
