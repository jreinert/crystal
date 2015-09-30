require "./data_frame"
class HTTP::WebSocketContinuationFrame < HTTP::WebSocketDataFrame
  OPCODE = Opcode::CONTINUATION
end
