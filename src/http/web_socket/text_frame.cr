require "./data_frame"

module HTTP
  class WebSocketTextFrame < WebSocketDataFrame
    OPCODE = Opcode::TEXT
  end
end
