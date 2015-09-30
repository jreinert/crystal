module ByteFormat
  abstract def encode(int : Int::Primitive)
  abstract def decode(klass : Int::Primitive.class, io : IO)
  abstract def encode(int : Float::Primitive)
  abstract def decode(klass : Float::Primitive.class, io : IO)

  def encode(float : Float32)
    encode((pointerof(float) as Int32*).value)
  end

  def decode(klass : Float32.class, io : IO)
    int = decode(Int32, io)
    (pointerof(int) as Float32*).value
  end

  def encode(float : Float64)
    encode((pointerof(float) as Int64*).value)
  end

  def decode(klass : Float64.class, io : IO)
    int = decode(Int64, io)
    (pointerof(int) as Float64*).value
  end

  module LittleEndian
    extend ByteFormat
  end

  module BigEndian
    extend ByteFormat
  end

  alias SystemEndian = LittleEndian
  alias NetworkEndian = BigEndian

  {% for mod in %w(LittleEndian BigEndian) %}
    module {{mod.id}}
      {% for type, i in %w(Int8 UInt8 Int16 UInt16 Int32 UInt32 Int64 UInt64) %}
        def self.encode(int : {{type.id}})
          buffer = (pointerof(int) as UInt8[{{2 ** (i / 2)}}]*).value
          buffer.reverse! unless SystemEndian == self
          buffer
        end

        def self.decode(klass : {{type.id}}.class, io : IO)
          buffer :: UInt8[{{2 ** (i / 2)}}]
          io.read_fully(buffer.to_slice)
          buffer.reverse! unless SystemEndian == self
          (buffer.to_slice.to_unsafe as Pointer({{type.id}})).value
        end
      {% end %}
    end
  {% end %}
end
