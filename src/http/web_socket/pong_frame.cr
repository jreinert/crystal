require "./control_frame"

class HTTP::WebSocketPongFrame < HTTP::WebSocketControlFrame
  OPCODE = Opcode::PONG
end
