require "socket"
require "http"
require "base64"
require "openssl"
require "uri"

class HTTP::WebSocket
  @[Flags]
  enum Flags : UInt8
    FINAL = 0x80
    RSV1 = 0x40
    RSV2 = 0x20
    RSV3 = 0x10
  end

  enum Opcode : UInt8
    CONTINUATION   = 0x0
    TEXT           = 0x1
    BINARY         = 0x2
    CLOSE          = 0x8
    PING           = 0x9
    PONG           = 0xA
  end

  MASK_BIT      = 128_u8
  VERSION       = 13

  record PacketInfo, opcode, size, final

  def initialize(@io)
    @header :: UInt8[2]
    @mask :: UInt8[4]
    @mask_offset = 0
    @opcode = Opcode::CONTINUATION
    @remaining = 0
  end

  abstract class StreamIO
    include IO

    def initialize(@websocket, @opcode, @masked, frame_size)
      @buffer = Slice(UInt8).new(frame_size)
      @pos = 0
    end

    def write(slice : Slice(UInt8))
      count = Math.min(@buffer.size - @pos, slice.size)
      (@buffer + @pos).copy_from(slice.pointer(count), count)
      @pos += count

      if @pos == @buffer.size
        flush(final: false)
      end

      if count < slice.size
        count += write(slice + count)
      end

      count
    end

    def read(slice : Slice(UInt8))
      raise "this IO is write-only"
    end

    def flush(final = true)
      @websocket.send(
        @buffer + (@pos % @buffer.size),
        @opcode,
        @masked,
        flags: final ? Flags::FINAL : Flags::None,
        flush: final
      )
      @opcode = Opcode::CONTINUATION
      @pos = 0
    end
  end

  class TextStreamIO < StreamIO
    def initialize(websocket, masked = false, frame_size = 1024)
      super(websocket, Opcode::TEXT, masked, frame_size)
    end
  end

  class BinaryStreamIO < StreamIO
    def initialize(websocket, masked = false, frame_size = 1024)
      super(websocket, Opcode::BINARY, masked, frame_size)
    end
  end

  {% for data_type, opcode in { "String" => "Opcode::TEXT", "Slice(UInt8)" => "Opcode::BINARY" } %}
    def send(data : {{data_type.id}}, masked = false)
      slice = {{data_type == "Slice(UInt8)" ? "data".id : "data.to_slice".id}}
      send(slice, {{opcode.id}}, masked)
    end
  {% end %}

  {% for type, io in { "text" => TextStreamIO, "binary" => BinaryStreamIO } %}
    def {{type.id}}_stream(masked = false, frame_size = 1024)
      stream_io = {{io}}.new(self, masked, frame_size)
      yield(stream_io)
      stream_io.flush
    end
  {% end %}

  def send(data : Slice(UInt8), opcode : Opcode, masked = false, flags = Flags::FINAL, flush = true)
    write_header(data.size, opcode, masked, flags)
    write_payload(data, masked)
    @io.flush if flush
  end

  def receive(buffer : Slice(UInt8))
    if @remaining == 0
      opcode = read_header
    else
      opcode = @opcode
    end

    read = read_payload(buffer)
    @remaining -= read
    PacketInfo.new(opcode, read.to_i, final? && @remaining == 0)
  end

  private def write_header(size, opcode, masked, flags)
    @io.write_byte(flags.value | opcode.value)

    mask = masked ? MASK_BIT : 0_u8
    if size <= 125
      @io.write_byte(size.to_u8 | mask)
    elsif size <= UInt16::MAX
      @io.write_byte(126_u8 | mask)
      @io.write_object(size.to_u16, ByteFormat::NetworkEndian)
    else
      @io.write_byte(127_u8 | mask)
      @io.write_object(size.to_u64, ByteFormat::NetworkEndian)
    end
  end

  private def write_payload(data, masked = false)
    return @io.write(data) unless masked

    mask_array = Random::DEFAULT.next_int.bytes(ByteFormat::NetworkEndian)
    @io.write mask_array.to_slice

    data.each_with_index do |byte, index|
      mask = mask_array[index % 4]
      @io.write_byte(byte ^ mask_array[index % 4])
    end
  end

  private def read_header
    # First byte: FIN (1 bit), RSV1,2,3 (3 bits), Opcode (4 bits)
    # Second byte: MASK (1 bit), Payload Length (7 bits)
    @io.read_fully(@header.to_slice)

    opcode = read_opcode
    @remaining = read_size

    # Read mask, if needed
    if masked?
      @io.read_fully(@mask.to_slice)
      @mask_offset = 0
    end

    opcode
  end

  private def read_opcode
    raw_opcode = @header[0] & 0x0f_u8
    parsed_opcode = Opcode.from_value?(raw_opcode)
    unless parsed_opcode
      raise "Invalid packet opcode: #{raw_opcode}"
    end

    if parsed_opcode == Opcode::CONTINUATION
       @opcode
     elsif control?
       parsed_opcode
     else
       @opcode = parsed_opcode
     end
  end

  private def read_size
    size = (@header[1] & 0x7f_u8).to_i
    if size == 126
      size = 0
      2.times { size <<= 8; size += @io.read_byte.not_nil! }
    elsif size == 127
      size = 0
      4.times { size <<= 8; size += @io.read_byte.not_nil! }
    end
    size
  end

  private def read_payload(buffer)
    count = Math.min(@remaining, buffer.size)
    if masked?
      count.times do |i|
        buffer[i] = @io.read_byte.not_nil! ^ @mask[@mask_offset % 4]
        @mask_offset += 1
      end
    else
      @io.read_fully(buffer[0, count])
    end

    count
  end

  private def control?
    (@header[0] & 0x08_u8) != 0_u8
  end

  private def final?
    (@header[0] & 0x80_u8) != 0_u8
  end

  private def masked?
    (@header[1] & 0x80_u8) != 0_u8
  end

  def close
  end

  # Opens a new websocket to the target host. This will also handle the handshake
  # and will raise an exception if the handshake did not complete successfully.
  #
  # ```
  # WebSocket.open("websocket.example.com", "/chat")              # Creates a new WebSocket to `websocket.example.com`
  # WebSocket.open("websocket.example.com", "/chat", ssl = true)  # Creates a new WebSocket with SSL to `ẁebsocket.example.com`
  # ```
  def self.open(host, path, port = nil, ssl = false)
    port = port || (ssl ? 443 : 80)
    socket = TCPSocket.new(host, port)
    socket = OpenSSL::SSL::Socket.new(socket) if ssl

    headers = HTTP::Headers.new
    headers["Host"] = "#{host}:#{port}"
    headers["Connection"] = "Upgrade"
    headers["Upgrade"] = "websocket"
    headers["Sec-WebSocket-Version"] = VERSION.to_s
    headers["Sec-WebSocket-Key"] = Base64.encode(StaticArray(UInt8, 16).new { rand(256).to_u8 })

    path = "/" if path.empty?
    handshake = HTTP::Request.new("GET", path, headers)
    handshake.to_io(socket)
    handshake_response = HTTP::Response.from_io(socket)
    unless handshake_response.status_code == 101
      raise Socket::Error.new("Handshake got denied. Status code was #{handshake_response.status_code}")
    end

    new(socket)
  end

  # Opens a new websocket using the information provided by the URI. This will also handle the handshake
  # and will raise an exception if the handshake did not complete successfully. This method will also raise
  # an exception if the URI is missing the host and/or the path.
  #
  # Please note that the scheme will only be used to identify if SSL should be used or not. Therefore, schemes
  # apart from `wss` and `https` will be treated as the default which is `ws`.
  #
  # ```
  # WebSocket.open(URI.parse("ws://websocket.example.com/chat"))        # Creates a new WebSocket to `websocket.example.com`
  # WebSocket.open(URI.parse("wss://websocket.example.com/chat"))       # Creates a new WebSocket with SSL to `websocket.example.com`
  # WebSocket.open(URI.parse("http://websocket.example.com:8080/chat")) # Creates a new WebSocket to `websocket.example.com` on port `8080`
  # ```
  def self.open(uri : URI | String)
    uri = URI.parse(uri) if uri.is_a?(String)

    if host = uri.host
      if path = uri.path
        ssl = uri.scheme == "https" || uri.scheme == "wss"
        return open(host, path, uri.port, ssl)
      end
    end

    raise ArgumentError.new("No host or path specified which are required.")
  end
end
