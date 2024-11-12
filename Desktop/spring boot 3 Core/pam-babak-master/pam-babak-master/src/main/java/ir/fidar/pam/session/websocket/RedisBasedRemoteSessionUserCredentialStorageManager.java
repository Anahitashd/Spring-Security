package ir.fidar.pam.session.websocket;

import ir.fidar.core.management.onmemoryresource.redis.RedisDataAccessor;
import ir.fidar.pam.domain.model.connection.Connection;
import ir.fidar.pam.domain.model.credential.UsernamePasswordCredential;
import ir.fidar.pam.domain.type.CredentialType;
import java.util.Set;
import org.springframework.stereotype.Component;

@Component
public class RedisBasedRemoteSessionUserCredentialStorageManager implements RemoteSessionUserCredentialStorageManager {
   private static final String USER_ENTRIES_STORAGE_KEY_PREFIX = "USER_REMOTE_SESSION_REMEMBER_ME_KEYS_";
   private static final String USER_CREDENTIALS_STORAGE_KEY_PREFIX = "USER_REMOTE_SESSION_REMEMBER_ME_CREDENTIALS_";
   private static final String STORAGE_USERNAME_FIELD = "username";
   private static final String STORAGE_PASSWORD_FIELD = "password";
   private static final int STORAGE_KEY_LIFETIME = 604800;
   private final RedisDataAccessor redisDataAccessor;

   public RedisBasedRemoteSessionUserCredentialStorageManager(RedisDataAccessor redisDataAccessor) {
      this.redisDataAccessor = redisDataAccessor;
   }

   @Override
   public UsernamePasswordCredential getCredential(String username, Connection connection) {
      String key = this.getCredentialKey(username, connection);
      UsernamePasswordCredential usernamePasswordCredential = null;
      if (this.redisDataAccessor.keyExists(key)) {
         String credUsername = this.redisDataAccessor.hash().getFieldValue(key, "username");
         if (credUsername != null) {
            String credPassword = this.redisDataAccessor.hash().getFieldValue(key, "password");
            if (credPassword != null) {
               usernamePasswordCredential = new UsernamePasswordCredential();
               usernamePasswordCredential.setUsername(credUsername);
               usernamePasswordCredential.setPassword(credPassword);
               usernamePasswordCredential.setType(CredentialType.USERNAME_PASSWORD);
               usernamePasswordCredential.setLabel("STORED");
            }
         }
      }

      return usernamePasswordCredential;
   }

   @Override
   public void save(String username, Connection connection, UsernamePasswordCredential usernamePasswordCredential) {
      String entriesKey = this.getEntriesKey(username);
      String credentialKey = this.getCredentialKey(username, connection);
      this.redisDataAccessor.set().addValue(entriesKey, credentialKey);
      this.redisDataAccessor.hash().set(credentialKey, "username", usernamePasswordCredential.getUsername());
      this.redisDataAccessor.hash().set(credentialKey, "password", usernamePasswordCredential.getPassword());
      this.redisDataAccessor.setLifeTime(credentialKey, 604800);
   }

   @Override
   public void delete(String username, Connection connection) {
      String entriesKey = this.getEntriesKey(username);
      String credentialKey = this.getCredentialKey(username, connection);
      this.redisDataAccessor.deleteKeys(credentialKey);
      this.redisDataAccessor.set().removeValues(entriesKey, credentialKey);
   }

   @Override
   public boolean exists(String username, Connection connection) {
      String entriesKey = this.getEntriesKey(username);
      if (!this.redisDataAccessor.keyExists(entriesKey)) {
         return false;
      } else {
         String credentialKey = this.getCredentialKey(username, connection);
         return this.redisDataAccessor.keyExists(credentialKey) && this.redisDataAccessor.set().contains(entriesKey, credentialKey);
      }
   }

   @Override
   public void delete(String username) {
      String entriesKey = this.getEntriesKey(username);
      if (this.redisDataAccessor.keyExists(entriesKey)) {
         Set<String> credentialKeys = this.redisDataAccessor.set().getAllValues(username);
         if (credentialKeys != null && !credentialKeys.isEmpty()) {
            this.redisDataAccessor.deleteKeys(credentialKeys.toArray(new String[0]));
         }

         this.redisDataAccessor.deleteKeys(entriesKey);
      }
   }

   private String getEntriesKey(String username) {
      return "USER_REMOTE_SESSION_REMEMBER_ME_KEYS_" + username.hashCode();
   }

   private String getCredentialKey(String username, Connection connection) {
      String key = username + connection.getType().toString() + connection.getIpAddress() + connection.getPort();
      return "USER_REMOTE_SESSION_REMEMBER_ME_CREDENTIALS_" + key.hashCode();
   }
}
