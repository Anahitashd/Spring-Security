package ir.fidar.pam.session.websocket;

import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;

public abstract class BridgeWebsocketHandler extends TextWebSocketHandler {
   public abstract void close(WebSocketSession var1);

   public abstract void setCloseStatus(WebsocketSessionCloseStatus var1);
}
