require "./control_frame"

class HTTP::WebSocketPingFrame < HTTP::WebSocketControlFrame
  OPCODE = Opcode::PING
end
