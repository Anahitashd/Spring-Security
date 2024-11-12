package ir.fidar.pam.domain.dto.connection;

public class TransparentConnectionPortMappingDto {
   private String ipAddress;
   private int port;
   private int listeningPort;

   public String getIpAddress() {
      return this.ipAddress;
   }

   public void setIpAddress(String ipAddress) {
      this.ipAddress = ipAddress;
   }

   public int getPort() {
      return this.port;
   }

   public void setPort(int port) {
      this.port = port;
   }

   public int getListeningPort() {
      return this.listeningPort;
   }

   public void setListeningPort(int listeningPort) {
      this.listeningPort = listeningPort;
   }
}
