package ir.fidar.pam.session;

import org.apache.guacamole.net.GuacamoleTunnel;

public interface Session {
   String getId();

   GuacamoleTunnel getTunnel();

   void open();

   void close();
}
