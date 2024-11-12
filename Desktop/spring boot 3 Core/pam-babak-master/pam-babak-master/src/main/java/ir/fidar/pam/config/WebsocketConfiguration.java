package ir.fidar.pam.config;

import ir.fidar.pam.session.websocket.BridgeWebsocketSessionHandler;
import ir.fidar.pam.session.websocket.BridgeWebsocketSessionInitializationHandshakeInterceptor;
import java.util.concurrent.Executors;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.scheduling.concurrent.ConcurrentTaskScheduler;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;
import org.springframework.web.socket.handler.PerConnectionWebSocketHandler;
import org.springframework.web.socket.server.HandshakeHandler;
import org.springframework.web.socket.server.HandshakeInterceptor;
import org.springframework.web.socket.server.support.DefaultHandshakeHandler;
import org.springframework.web.socket.server.support.HttpSessionHandshakeInterceptor;

@Configuration
@EnableWebSocket
public class WebsocketConfiguration implements WebSocketConfigurer {
   public static final String PROTOCOL = "fidar-pam";
   private final BridgeWebsocketSessionInitializationHandshakeInterceptor initializationHandshakeInterceptor;

   public WebsocketConfiguration(BridgeWebsocketSessionInitializationHandshakeInterceptor initializationHandshakeInterceptor) {
      this.initializationHandshakeInterceptor = initializationHandshakeInterceptor;
   }

   public void registerWebSocketHandlers(WebSocketHandlerRegistry webSocketHandlerRegistry) {
      webSocketHandlerRegistry.addHandler(this.webSocketHandler(), new String[]{"/api/remote-session/**"})
         .addInterceptors(new HandshakeInterceptor[]{new HttpSessionHandshakeInterceptor(), this.initializationHandshakeInterceptor})
         .setHandshakeHandler(new DefaultHandshakeHandler())
         .setAllowedOrigins(new String[]{"*"});
   }

   @Bean
   public WebSocketHandler webSocketHandler() {
      return new PerConnectionWebSocketHandler(BridgeWebsocketSessionHandler.class);
   }

   @Bean
   public TaskScheduler taskScheduler() {
      return new ConcurrentTaskScheduler(Executors.newSingleThreadScheduledExecutor());
   }

   @Bean
   public HandshakeHandler handshakeHandler() {
      DefaultHandshakeHandler defaultHandshakeHandler = new DefaultHandshakeHandler();
      defaultHandshakeHandler.setSupportedProtocols(new String[]{"fidar-pam"});
      return defaultHandshakeHandler;
   }
}
