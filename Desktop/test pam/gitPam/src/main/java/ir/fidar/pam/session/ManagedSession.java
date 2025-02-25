package ir.fidar.pam.session;

import ir.fidar.pam.domain.model.accessrule.AccessRule;
import ir.fidar.pam.domain.model.accessrule.AccessRuleConnection;
import ir.fidar.pam.domain.model.connection.Connection;
import ir.fidar.pam.management.Markers;
import ir.fidar.pam.session.tunnel.StreamInterceptorTunnel;
import ir.fidar.pam.session.websocket.BridgeWebsocketHandler;
import java.time.Instant;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.net.GuacamoleSocket;
import org.apache.guacamole.net.GuacamoleTunnel;
import org.apache.guacamole.net.SimpleGuacamoleTunnel;
import org.apache.guacamole.protocol.GuacamoleClientInformation;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ManagedSession implements Session {
   private static final Logger LOGGER = LogManager.getLogger();
   private final String uuid;
   private final AccessRuleConnection accessRuleConnection;
   private final GuacamoleSocket socket;
   private GuacamoleTunnel tunnel;
   private final String user;
   private final long startTime;
   private long stopTime;
   private ManagedSession.Status status;
   private final GuacamoleClientInformation clientInformation;
   private final BridgeWebsocketHandler websocketHandler;

   public ManagedSession(
      String uuid,
      AccessRule accessRule,
      AccessRuleConnection accessRuleConnection,
      String user,
      GuacamoleSocket socket,
      GuacamoleClientInformation clientInformation,
      BridgeWebsocketHandler websocketHandler
   ) {
      this.uuid = uuid;
      this.accessRuleConnection = accessRuleConnection;
      this.user = user;
      this.socket = socket;
      this.clientInformation = clientInformation;
      this.websocketHandler = websocketHandler;
      this.status = ManagedSession.Status.OPEN;
      this.startTime = Instant.now().getEpochSecond();
   }

   public AccessRule getAccessRule() {
      return this.accessRuleConnection.getAccessRule();
   }

   public Connection getConnection() {
      return this.accessRuleConnection.getConnection();
   }

   public AccessRuleConnection getAccessRuleConnection() {
      return this.accessRuleConnection;
   }

   public String getUser() {
      return this.user;
   }

   public long getStartTime() {
      return this.startTime;
   }

   public long getStopTime() {
      return this.stopTime;
   }

   @Override
   public String getId() {
      return this.uuid;
   }

   @Override
   public GuacamoleTunnel getTunnel() {
      return this.tunnel;
   }

   public ManagedSession.Status getStatus() {
      return this.status;
   }

   public BridgeWebsocketHandler getWebsocketHandler() {
      return this.websocketHandler;
   }

   public GuacamoleClientInformation getClientInformation() {
      return this.clientInformation;
   }

   @Override
   public void open() {
      this.tunnel = new StreamInterceptorTunnel(new SimpleGuacamoleTunnel(this.socket));
      LOGGER.debug(Markers.SESSION, "Bridge tunnel is opened and status is set to 'OPEN' for session '{}'", this.uuid);
   }

   @Override
   public void close() {
      try {
         this.stopTime = Instant.now().getEpochSecond();
         this.status = ManagedSession.Status.CLOSE;
         if (this.tunnel != null && this.tunnel.isOpen()) {
            this.tunnel.close();
         }

         LOGGER.debug(Markers.SESSION, "Bridge tunnel is closed and status is set to 'CLOSE' for session '{}'", this.uuid);
      } catch (GuacamoleException var2) {
         LOGGER.error(Markers.SESSION, "An unexpected error occurred on closing bridge tunnel for session '{}'", this.uuid, var2);
      }
   }

   public static enum Status {
      OPEN,
      CLOSE;
   }
}
