package ir.fidar.pam.session;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class SessionManager {
   private static final ConcurrentMap<String, Session> SESSIONS = new ConcurrentHashMap<>();

   public static Session getSession(String id) {
      return SESSIONS.get(id);
   }

   public static Set<Session> getAllSessions() {
      return new HashSet<>(SESSIONS.values());
   }

   public static Session terminateSession(String id) {
      if (SESSIONS.containsKey(id)) {
         Session session = SESSIONS.remove(id);
         session.close();
         return session;
      } else {
         return null;
      }
   }

   public static void terminateSessionSoftly(String id) {
      SESSIONS.remove(id);
   }

   public static void registerSession(Session session) {
      SESSIONS.put(session.getId(), session);
   }

   public static int getTotalNumberOfSessions() {
      return SESSIONS.size();
   }

   public static SessionManager.SessionNumber getNumberOfSessionsOverSpecificConnection(String connectionName, String username) {
      int sessionsOverSpecificConnection = 0;
      int sessionsOverSpecificConnectionByUser = 0;

      for (Session session : SESSIONS.values()) {
         ManagedSession managedSession = (ManagedSession)session;
         if (managedSession.getConnection().getName().equalsIgnoreCase(connectionName)) {
            sessionsOverSpecificConnection++;
         }

         if (managedSession.getUser().equalsIgnoreCase(username)) {
            sessionsOverSpecificConnectionByUser++;
         }
      }

      return new SessionManager.SessionNumber(sessionsOverSpecificConnection, sessionsOverSpecificConnectionByUser);
   }

   public static class SessionNumber {
      private int numberOfSessionsOverSpecificConnection;
      private int numberOfSessionsOverSpecificConnectionEstablishedBySpecificUser;

      public SessionNumber(int numberOfSessionsOverSpecificConnection, int numberOfSessionsOverSpecificConnectionEstablishedBySpecificUser) {
         this.numberOfSessionsOverSpecificConnection = numberOfSessionsOverSpecificConnection;
         this.numberOfSessionsOverSpecificConnectionEstablishedBySpecificUser = numberOfSessionsOverSpecificConnectionEstablishedBySpecificUser;
      }

      public int getNumberOfSessionsOverSpecificConnection() {
         return this.numberOfSessionsOverSpecificConnection;
      }

      public void setNumberOfSessionsOverSpecificConnection(int numberOfSessionsOverSpecificConnection) {
         this.numberOfSessionsOverSpecificConnection = numberOfSessionsOverSpecificConnection;
      }

      public int getNumberOfSessionsOverSpecificConnectionEstablishedBySpecificUser() {
         return this.numberOfSessionsOverSpecificConnectionEstablishedBySpecificUser;
      }

      public void setNumberOfSessionsOverSpecificConnectionEstablishedBySpecificUser(int numberOfSessionsOverSpecificConnectionEstablishedBySpecificUser) {
         this.numberOfSessionsOverSpecificConnectionEstablishedBySpecificUser = numberOfSessionsOverSpecificConnectionEstablishedBySpecificUser;
      }
   }
}
