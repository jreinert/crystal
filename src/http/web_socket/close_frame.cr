require "./control_frame"

class HTTP::WebSocketCloseFrame < HTTP::WebSocketControlFrame
  OPCODE = Opcode::CLOSE
end
