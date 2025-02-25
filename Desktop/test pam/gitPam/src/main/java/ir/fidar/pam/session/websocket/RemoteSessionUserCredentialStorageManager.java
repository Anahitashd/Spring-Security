package ir.fidar.pam.session.websocket;

import ir.fidar.pam.domain.model.connection.Connection;
import ir.fidar.pam.domain.model.credential.UsernamePasswordCredential;

public interface RemoteSessionUserCredentialStorageManager {
   UsernamePasswordCredential getCredential(String var1, Connection var2);

   void save(String var1, Connection var2, UsernamePasswordCredential var3);

   void delete(String var1);

   void delete(String var1, Connection var2);

   boolean exists(String var1, Connection var2);
}
