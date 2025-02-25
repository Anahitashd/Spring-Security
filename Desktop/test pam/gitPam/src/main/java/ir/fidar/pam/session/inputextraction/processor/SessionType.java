package ir.fidar.pam.session.inputextraction.processor;

import ir.fidar.pam.domain.type.ConnectionType;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public enum SessionType {
   CONSOLE(Stream.of(ConnectionType.SSH, ConnectionType.TELNET).collect(Collectors.toSet())),
   GRAPHICAL(Stream.of(ConnectionType.RDP, ConnectionType.VNC).collect(Collectors.toSet()));

   private final Set<ConnectionType> connectionTypes;

   private SessionType(Set<ConnectionType> connectionTypes) {
      this.connectionTypes = connectionTypes;
   }

   public Set<ConnectionType> getConnectionTypes() {
      return this.connectionTypes;
   }
}
