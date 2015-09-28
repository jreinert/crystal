require "secure_random"

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

    def initialize(@key = SecureRandom.random_bytes(4) : Slice(UInt8))
      super()
      @index = 0
    end

    def read(slice : Slice(UInt8))
      count = super
      @index += count
      count
    end

    def write(slice : Slice(UInt8))
      masked_slice = Slice(UInt8).new(slice.size)
      slice.each_with_index do |byte, index|
        mask = @key[(@index % 4 + index) % 4]
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

  def mask(key)
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

  def header
    @header ||= begin
      size_slice = self.size_slice
      header_size = size_slice.size + (masked? ? 5 : 1)
      slice = Slice(UInt8).new(header_size)
      slice[0] |= flags.value
      slice[0] |= opcode.value
      slice[1] |= MASKED if masked?
      slice[1] |= size_slice[0]
      (slice + 2).copy_from((size_slice + 1).pointer(size_slice.size - 1), size_slice.size - 1)
      if masked?
        mask_io = @payload as MaskIO
        (slice + (1 + size_slice.size)).copy_from(mask_io.key.pointer(4), 4)
      end

      slice
    end
  end

  def to_io(io)
    io.write(header)
    buffer = Slice(UInt8).new(1024)
    payload.rewind
    while (count = payload.read(buffer)) != 0
      io.write(buffer[0, count])
    end
  end

  macro def self.from_io(io) : WebSocketFrame
    header :: UInt8[2]
    io.read_fully(header.to_slice)
    opcode = opcode_from(header[0])
    frame = case(opcode)
    {% for subclass in @type.subclasses %}
      {% unless subclass.abstract? %}
        when {{subclass.id}}::OPCODE then {{subclass.id}}.new
      {% end %}
    {% end %}
    else raise "no frame implemented for opcode #{opcode}"
    end

    frame.flags_from(header[0])
    size = header[1] & ~MASKED
    if size == EXTENDED_SIZE
      size = io.read_byte.not_nil!.to_u16 << 8
      size |= io.read_byte.not_nil!
    elsif size == EXTRA_EXTENDED_SIZE
      size = 0_u64
      8.times do |i|
        size << 8
        size |= io.read_byte.not_nil!
      end
    end

    if (header[1] & MASKED) != 0
      masking_key :: UInt8[4]
      io.read_fully(masking_key.to_slice)
      frame.mask(masking_key.to_slice)
    end

    frame.read_payload(io, size)

    frame
  end

  protected def read_payload(io, size)
    buffer = Slice(UInt8).new(1024)
    left = size
    loop do
      break if left == 0
      count = Math.min(buffer.size, left)
      buffer = buffer[0, count]
      io.read(buffer)
      payload.write(buffer)
      left -= count
    end
  end

  protected def size_slice
    case(payload_size)
    when 0..125
      Slice(UInt8).new(1) { payload_size.to_u8 }
    when 126..0xffff
      slice = Slice(UInt8).new(3)
      slice[0] = EXTENDED_SIZE
      slice[1] = (payload_size >> 7).to_u8
      slice[2] = (payload_size & 0x00ff).to_u8
      slice
    else
      slice = Slice(UInt8).new(9)
      slice[0] = EXTRA_EXTENDED_SIZE
      mask = 0xff_00_00_00_00_00_00_00_u64
      8.times do |i|
        slice[1 + i] = ((payload_size & mask) >> (8 * (7 - i))).to_u8
        mask >>= 8
      end
      slice
    end
  end
end
