require "spec"
require "http"
require "secure_random"

class TestFrame < HTTP::WebSocketFrame
  OPCODE = Opcode::TEST
end

describe HTTP::WebSocketFrame do
  describe ".from_io" do
    it "reads the correct class" do
      io = StringIO.new
      io.write_byte(TestFrame::OPCODE.value)
      io.write_byte(0_u8) # size of 0
      io.rewind

      frame = HTTP::WebSocketFrame.from_io(io)
      io.gets.should be_nil
      frame.should be_a(TestFrame)
    end

    it "assigns the correct opcode" do
      io = StringIO.new
      io.write_byte(TestFrame::OPCODE.value)
      io.write_byte(0_u8) # size of 0
      io.rewind

      frame = HTTP::WebSocketFrame.from_io(io)
      frame.opcode.should eq(TestFrame::OPCODE)
    end

    it "assigns final and rsv1-3 attributes correctly" do
      io = StringIO.new
      io.write_byte(TestFrame::Flags::FINAL.value | TestFrame::OPCODE.value)
      io.write_byte(0_u8) # size of 0
      io.rewind

      frame = HTTP::WebSocketFrame.from_io(io)
      frame.final?.should be_true
      frame.rsv1?.should be_false
      frame.rsv2?.should be_false
      frame.rsv3?.should be_false

      io.rewind
      io.write_byte(
        (TestFrame::Flags::RSV1 | TestFrame::Flags::RSV3).value |
        TestFrame::OPCODE.value
      )
      io.rewind

      frame = HTTP::WebSocketFrame.from_io(io)
      frame.final?.should be_false
      frame.rsv1?.should be_true
      frame.rsv2?.should be_false
      frame.rsv3?.should be_true
    end

    it "reads the unmasked payload correctly when size < 125" do
      io = StringIO.new
      io.write_byte(TestFrame::OPCODE.value)
      io.write_byte(6_u8) # size of 6
      io.write("foobar".to_slice)
      io.rewind

      frame = HTTP::WebSocketFrame.from_io(io)
      frame.masked?.should be_false
      io.gets.should be_nil
      frame.payload.to_s.should eq("foobar")
    end

    it "reads the masked payload correctly when size < 125" do
      io = StringIO.new
      io.write_byte(TestFrame::OPCODE.value)
      io.write_byte(TestFrame::MASKED | 6_u8) # masked with size of 6
      masking_key = SecureRandom.random_bytes(4)
      io.write(masking_key)
      "foobar".each_byte.each_with_index do |byte, index|
        io.write_byte(byte ^ masking_key[index % 4])
      end
      io.rewind

      frame = HTTP::WebSocketFrame.from_io(io)
      frame.masked?.should be_true
      io.gets.should be_nil
      frame.payload.to_s.should eq("foobar")
    end

    it "reads the unmasked payload correctly when 125 < size <= 0xffff" do
      io = StringIO.new
      io.write_byte(TestFrame::OPCODE.value)
      io.write_byte(TestFrame::EXTENDED_SIZE)
      size = StaticArray(UInt8, 2).new(0xff_u8)
      io.write(size.to_slice) # size of 0xffff
      payload = StringIO.new
      0xffff.times do
        a = 'a'.ord.to_u8
        payload.write_byte(a)
        io.write_byte(a)
      end
      io.rewind

      frame = HTTP::WebSocketFrame.from_io(io)
      frame.masked?.should be_false
      io.gets.should be_nil
      frame.payload.to_s.should eq(payload.to_s)
    end

    it "reads the masked payload correctly when 125 < size <= 0xffff" do
      io = StringIO.new
      io.write_byte(TestFrame::OPCODE.value)
      io.write_byte(TestFrame::MASKED | TestFrame::EXTENDED_SIZE)
      size = StaticArray(UInt8, 2).new(0xff_u8)
      io.write(size.to_slice) # size of 0xffff
      masking_key = SecureRandom.random_bytes(4)
      io.write(masking_key)
      payload = StringIO.new
      0xffff.times do |index|
        byte = 'a'.ord.to_u8
        payload.write_byte(byte)
        io.write_byte(byte ^ masking_key[index % 4])
      end
      io.rewind

      frame = HTTP::WebSocketFrame.from_io(io)
      frame.masked?.should be_true
      io.gets.should be_nil
      frame.payload.to_s.should eq(payload.to_s)
    end

    pending "reads the unmasked payload correctly when size > 0xffffffff" do
      io = IO.pipe(true, true)
      writer = Thread.new do
        io.write_byte(TestFrame::OPCODE.value)
        io.write_byte(TestFrame::EXTRA_EXTENDED_SIZE)
        size = StaticArray(UInt8, 8).new(0_u8)
        size[0] = 0x01_u8
        io.write(size.to_slice) # size of 0x01_00_00_00_00
        0x01_00_00_00_00.times do
          a = 'a'.ord.to_u8
          payload.write_byte(a)
          io.write_byte(a)
        end
      end

      frame = HTTP::WebSocketFrame.from_io(io)
      frame.masked?.should be_false
      io.gets.should be_nil
      frame.payload.should eq(payload)
    end
  end

  describe ".to_io" do
    it "writes a correct header" do
      frame = TestFrame.new
      io = StringIO.new
      frame.to_io(io)
      io.rewind

      header :: UInt8[2]
      io.read_fully(header.to_slice)
      io.gets.should be_nil
      (header[0] & TestFrame::Flags::FINAL.value).should_not eq(0)
      (header[0] & 0x0f).should eq(TestFrame::OPCODE.value)
      (header[1] & TestFrame::MASKED).should eq(0)
      (header[1] & ~TestFrame::MASKED).should eq(0) # size
    end

    it "writes a correct size for payload sizes < 125" do
      frame = TestFrame.new
      frame.payload << "foobar" # size of 6
      io = StringIO.new
      frame.to_io(io)
      io.rewind

      header :: UInt8[2]
      io.read_fully(header.to_slice)
      (header[1] & ~TestFrame::MASKED).should eq(6) # size
    end

    it "writes the payload correctly for payload sizes < 125" do
      frame = TestFrame.new
      frame.payload << "foobar" # size of 6
      io = StringIO.new
      frame.to_io(io)
      io.rewind

      2.times { io.read_byte.not_nil! } # skipping header
      payload = Slice(UInt8).new(6)
      io.read_fully(payload)
      String.new(payload).should eq("foobar")
      io.gets.should be_nil
    end

    it "writes a correct size for 125 < payload sizes <= 0xffff" do
      frame = TestFrame.new
      frame.payload << "a" * 126
      io = StringIO.new
      frame.to_io(io)
      io.rewind
      header :: UInt8[2]
      io.read_fully(header.to_slice)

      (header[1] & ~TestFrame::MASKED).should eq(TestFrame::EXTENDED_SIZE)
      size :: UInt8[2]
      io.read_fully(size.to_slice)
      size.reverse! # network byte order

      size_value = (pointerof(size) as Pointer(UInt16)).value
      size_value.should eq(126)
    end

    it "writes the payload correctly for payload sizes < 125" do
      frame = TestFrame.new
      frame.payload << "a" * 126
      io = StringIO.new
      frame.to_io(io)
      io.rewind
      4.times { io.read_byte.not_nil! } # skipping header and exended size

      payload = Slice(UInt8).new(126)
      io.read_fully(payload)
      String.new(payload).should eq("a" * 126)
      io.gets.should be_nil
    end

    it "masks the payload correctly" do
      frame = TestFrame.new
      key = SecureRandom.random_bytes(4)
      frame.mask(key)
      frame.payload << "a" * 126
      io = StringIO.new
      frame.to_io(io)
      io.rewind
      8.times { io.read_byte.not_nil! } # skipping header, extended size and mask key

      a = 'a'.ord.to_u8
      payload = String.build do |builder|
        126.times do |i|
          builder.write_byte(io.read_byte.not_nil! ^ key[i % 4])
        end
      end
      payload.should eq("a" * 126)
      io.gets.should be_nil
    end
  end
end
