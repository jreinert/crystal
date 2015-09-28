module ByteFormat
  abstract def encode(int : Int::Primitive)
  abstract def decode(int : Int::Primitive.class)
  abstract def encode(int : Float::Primitive)
  abstract def decode(int : Float::Primitive.class)

  def encode(float : Float32)
    encode((pointerof(float) as Int32*).value)
  end

  def encode(float : Float64)
    encode((pointerof(float) as Int64*).value)
  end

  module LittleEndian
    extend ByteFormat
  end

  module BigEndian
    extend ByteFormat
  end

  alias SystemEndian = LittleEndian

  {% for mod in %w(LittleEndian BigEndian) %}
    module {{mod.id}}
      {% for type, i in %w(Int8 UInt8 Int16 UInt16 Int32 UInt32 Int64 UInt64) %}
        def self.encode(int : {{type.id}})
          buffer = (pointerof(int) as UInt8[{{2 ** (i / 2)}}]*).value
          buffer.reverse! unless SystemEndian == self
          buffer
        end
      {% end %}
    end
  {% end %}
end
