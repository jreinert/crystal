abstract class HTTP::WebSocketFrame
  @[Flags]
  enum Flags : UInt8
    FINAL = 0x80
    RSV1  = 0x40
    RSV2  = 0x20
    RSV3  = 0x10
  end

  MASKED              = 0x80_u8
  EXTENDED_SIZE       = 0x7F_u8
  EXTRA_EXTENDED_SIZE = 0x7F_u8

  getter flags

  def flags=(flags : Flags)
    @flags = flags
  end

  macro def flags_from(byte : UInt8) : Nil
    flags = Flags::None
    {% for flag in Flags.constants %}
      {% unless ["None", "All"].includes?("#{flag}") %}
        flag = byte & Flags::{{flag}}.value
        flags |= Flags.from_value(flag)
      {% end %}
    {% end %}
    @flags = flags
    nil
  end

  {% for flag in Flags.constants %}
    {% unless ["None", "All"].includes?("#{flag}") %}
      def {{flag.downcase}}?
        @flags & Flags::{{flag}} == Flags::{{flag}}
      end

      def {{flag.downcase}}=(value)
        if value
          @flags |= Flags::{{flag}}
        else
          @flags &= ~Flags::{{flag}}
        end
      end
    {% end %}
  {% end %}

  enum Opcode : UInt8
    CONTINUATION   = 0x0
    TEXT           = 0x1
    BINARY         = 0x2
    CLOSE          = 0x8
    PING           = 0x9
    PONG           = 0xA
    TEST           = 0xF
  end

  class MaskIO < StringIO
    getter key

    def initialize(@key = generate_key : Int32)
      super()
      @index = 0
    end

    def self.generate_key
      while (key = Random::DEFAULT.next_int) == 0
      end
      key
    end

    def read(slice : Slice(UInt8))
      count = super
      @index += count
      count
    end

    def write(slice : Slice(UInt8))
      masked_slice = Slice(UInt8).new(slice.size)
      key_bytes = @key.bytes(ByteFormat::NetworkEndian)
      slice.each_with_index do |byte, index|
        mask = key_bytes[(@index % 4 + index) % 4]
        masked_slice[index] = byte ^ mask
      end

      count = super(masked_slice)
      @index += count
      count
    end
  end

  getter opcode
  getter? masked

  def initialize(@flags = Flags::FINAL : Flags, @masked = false)
    @opcode = {{OPCODE}}
    @payload = masked? ? MaskIO.new : StringIO.new
  end

  def mask(key : Int32)
    return if payload.try { |p| p.is_a?(MaskIO) && p.key } == key
    mask_io = MaskIO.new(key)
    buffer = Slice(UInt8).new(1024)
    while (count = payload.read(buffer)) != 0
      mask_io.write(buffer[0, count])
    end

    @payload = mask_io
    @masked = true
  end

  def payload
    if masked?
      @payload as MaskIO
    else
      @payload
    end
  end

  def unmask
    return unless masked?
    payload = StringIO.new
    buffer = Slice(UInt8).new(1024)
    while (count = @payload.read(buffer)) != 0
      payload.write(buffer[0, count])
    end

    @payload = payload
    @masked = false
  end

  def self.opcode_from(byte : UInt8)
    raw_opcode = byte & 0x0f
    return Opcode.from_value?(raw_opcode) || raise "unknown opcode 0x#{byte.to_s(16)}"
  end

  def payload_size
    payload.size
  end

  def write_header(io, format)
    io.write_byte(flags.value | opcode.value)
    write_size(io, format)
    payload = @payload
    io.write_object(payload.key, format) if payload.is_a?(MaskIO)
  end

  private def write_size(io, format)
    size = payload_size
    masked_bit = masked? ? MASKED : 0_u8
    if size < 0x7e
      io.write_byte(masked_bit | size.to_u8)
    elsif size <= 0xffff
      io.write_byte(masked_bit | EXTENDED_SIZE)
      io.write_object(size.to_u16, format)
    else
      io.write_byte(masked_bit | EXTRA_EXTENDED_SIZE)
      io.write_object(size.to_u64, format)
    end
  end

  def to_io(io, format)
    write_header(io, format)
    payload.rewind
    IO.copy(payload, io)
  end

  macro def self.from_io(io, format) : WebSocketFrame
    header :: UInt8[2]
    io.read_fully(header.to_slice)
    opcode = opcode_from(header[0])
    frame = case(opcode)
    {% for subclass in @type.all_subclasses.reject(&.abstract?) %}
      when {{subclass.id}}::OPCODE then {{subclass.id}}.new
    {% end %}
    else raise "no frame implemented for opcode #{opcode}"
    end

    frame.flags_from(header[0])
    size = header[1] & ~MASKED
    if size == EXTENDED_SIZE
      size = io.read_object(UInt16, format)
    elsif size == EXTRA_EXTENDED_SIZE
      size = io.read_object(UInt64, format)
    end

    if (header[1] & MASKED) != 0
      masking_key = io.read_object(Int32, format)
      frame.mask(masking_key)
    end

    IO.copy(io, frame.payload)

    frame
  end
end
