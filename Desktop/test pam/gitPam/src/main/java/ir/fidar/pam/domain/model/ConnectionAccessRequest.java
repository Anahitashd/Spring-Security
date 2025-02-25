package ir.fidar.pam.domain.model;

import ir.fidar.core.domain.model.DescriptiveBaseEntity;
import ir.fidar.core.domain.util.constraint.ValidIp;
import ir.fidar.core.security.validation.XssProtected;
import ir.fidar.pam.domain.model.management.User;
import ir.fidar.pam.domain.type.ConnectionAccessRequestStatus;
import ir.fidar.pam.domain.type.ConnectionType;
import ir.fidar.pam.domain.type.FileTransferMode;
import ir.fidar.pam.domain.util.converter.attribbute.ConnectionAccessRequestStatusConverter;
import ir.fidar.pam.domain.util.converter.attribbute.FileTransferModeConverter;
import ir.fidar.pam.domain.util.converter.attribbute.connection.ConnectionTypeConverter;
import java.util.Objects;
import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

@Entity
@Table(
   name = "tb_connection_access_request"
)
public class ConnectionAccessRequest extends DescriptiveBaseEntity {
   @NotBlank(
      message = "blank.identifier"
   )
   private String identifier;
   @Min(
      value = 1L,
      message = "lt_min.expirationTime"
   )
   @Max(
      value = 4000000000L,
      message = "gt_max.expirationTime"
   )
   private long applicationTime;
   @NotBlank(
      message = "blank.ipAddress"
   )
   @ValidIp
   @XssProtected
   private String ipAddress;
   @Min(
      value = 1L,
      message = "lt_min.port"
   )
   @Max(
      value = 65535L,
      message = "gt_max.port"
   )
   private int port;
   @NotNull(
      message = "null.type"
   )
   @Convert(
      converter = ConnectionTypeConverter.class
   )
   private ConnectionType type;
   @NotNull(
      message = "null.clipboard"
   )
   private boolean clipboardEnabled;
   @NotNull(
      message = "fileTransferMode.null"
   )
   @Convert(
      converter = FileTransferModeConverter.class
   )
   private FileTransferMode fileTransferMode;
   @NotNull(
      message = "status.null"
   )
   @Convert(
      converter = ConnectionAccessRequestStatusConverter.class
   )
   private ConnectionAccessRequestStatus status;
   @XssProtected
   private String adminReviewNote;
   @ManyToOne(
      fetch = FetchType.LAZY
   )
   @JoinColumn(
      name = "user_id"
   )
   private User user;

   public String getIdentifier() {
      return this.identifier;
   }

   public void setIdentifier(String identifier) {
      this.identifier = identifier;
   }

   public long getApplicationTime() {
      return this.applicationTime;
   }

   public void setApplicationTime(long applicationTime) {
      this.applicationTime = applicationTime;
   }

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

   public ConnectionType getType() {
      return this.type;
   }

   public void setType(ConnectionType type) {
      this.type = type;
   }

   public boolean isClipboardEnabled() {
      return this.clipboardEnabled;
   }

   public void setClipboardEnabled(boolean clipboard) {
      this.clipboardEnabled = clipboard;
   }

   public FileTransferMode getFileTransferMode() {
      return this.fileTransferMode;
   }

   public void setFileTransferMode(FileTransferMode fileTransferMode) {
      this.fileTransferMode = fileTransferMode;
   }

   public ConnectionAccessRequestStatus getStatus() {
      return this.status;
   }

   public void setStatus(ConnectionAccessRequestStatus status) {
      this.status = status;
   }

   public String getAdminReviewNote() {
      return this.adminReviewNote;
   }

   public void setAdminReviewNote(String adminCheckNote) {
      this.adminReviewNote = adminCheckNote;
   }

   public User getUser() {
      return this.user;
   }

   public void setUser(User applicant) {
      this.user = applicant;
   }

   @Override
   public boolean equals(Object o) {
      if (this == o) {
         return true;
      } else if (o != null && this.getClass() == o.getClass()) {
         ConnectionAccessRequest that = (ConnectionAccessRequest)o;
         return this.identifier.equals(that.identifier);
      } else {
         return false;
      }
   }

   @Override
   public int hashCode() {
      return Objects.hash(this.identifier);
   }
}
