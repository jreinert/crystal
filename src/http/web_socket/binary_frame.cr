require "./data_frame"
class HTTP::WebSocketBinaryFrame < HTTP::WebSocketDataFrame
  OPCODE = Opcode::BINARY
end
