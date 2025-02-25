package ir.fidar.pam.session.websocket;

import org.springframework.web.socket.CloseStatus;

public enum WebsocketSessionCloseStatus {
   INVALID_REQUEST_PARAMETERS(4000, "Request Parameters Are Invalid"),
   UNAUTHORIZED_USER(4030, "Unauthorized User"),
   SESSION_NOT_FOUND(4040, "Requested Session Not Found"),
   UNSUPPORTED_SUB_PROTOCOL(4050, "Unsupported Sub-Protocol"),
   INTERNAL_ERROR(4500, "Unexpected Error"),
   BRIDGE_IO_ERROR(4501, "Bridge Connection IO Error"),
   BRIDGE_UNEXPECTED_ERROR(4502, "Bridge Server Error"),
   BRIDGE_CONNECTION_ERROR(4503, "Bridge Server Connection Error"),
   DISABLED_ACCESS_RULE(4001, "Session Is Disabled"),
   EXPIRED_ACCESS_RULE(4002, "Session Is expired"),
   CREDENTIAL_NOT_FOUND(4003, "Credential Not Fount"),
   EXCEEDED_MAX_CONCURRENT_SESSIONS(4004, "Max Concurrent Sessions Limitation Exceeded"),
   EXCEEDED_MAX_CONCURRENT_SESSIONS_PER_USER(4005, "Max Concurrent Sessions Limitation Per User Exceeded"),
   TERMINATED_BY_INPUT_CONSTRAINT(4100, "Session Terminated By Input Constraint Handler"),
   TERMINATED_BY_ACCESSIBILITY_TIME_CONSTRAINT(4101, "Session Terminated By Accessibility Time Constraint"),
   TERMINATED_DUE_TO_INACTIVITY(4102, "Session Terminated Due To Inactivity"),
   TERMINATED_BY_PRIVILEGED_USER(4103, "Session Terminated By A Privileged User"),
   NORMAL(CloseStatus.NORMAL.getCode(), "Normal");

   private int code;
   private String status;

   private WebsocketSessionCloseStatus(int code, String status) {
      this.code = code;
      this.status = status;
   }

   public int getCode() {
      return this.code;
   }

   public String getStatus() {
      return this.status;
   }
}
