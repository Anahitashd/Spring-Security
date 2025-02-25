package ir.fidar.pam.session;

import ir.fidar.core.da.core.query.builder.NativeQueryBuilder;
import ir.fidar.core.da.core.repository.NativeQueryBasedReadRepository;
import ir.fidar.core.util.StringUtils;
import ir.fidar.core.util.filter.QueryAndFilterUtils;
import ir.fidar.pam.domain.model.Bridge;
import ir.fidar.pam.domain.model.accessrule.AccessRule;
import ir.fidar.pam.domain.model.accessrule.AccessRuleConnection;
import ir.fidar.pam.domain.model.connection.Connection;
import ir.fidar.pam.domain.model.connection.RdpConnection;
import ir.fidar.pam.domain.model.connection.RdpConnectionRemoteApplication;
import ir.fidar.pam.domain.model.connection.SshConnection;
import ir.fidar.pam.domain.model.connection.TelnetConnection;
import ir.fidar.pam.domain.model.connection.VncConnection;
import ir.fidar.pam.domain.model.credential.Credential;
import ir.fidar.pam.domain.model.credential.DomainCredential;
import ir.fidar.pam.domain.model.credential.PrivateKeyCredential;
import ir.fidar.pam.domain.model.credential.UsernamePasswordCredential;
import ir.fidar.pam.domain.type.ConnectionType;
import ir.fidar.pam.domain.type.FileTransferMode;
import java.util.HashMap;
import java.util.Map;
import org.springframework.stereotype.Component;

@Component
public class BridgeSessionConfigurationParameterResolver {
   private final NativeQueryBasedReadRepository nativeQueryBasedReadRepository;

   public BridgeSessionConfigurationParameterResolver(NativeQueryBasedReadRepository nativeQueryBasedReadRepository) {
      this.nativeQueryBasedReadRepository = nativeQueryBasedReadRepository;
   }

   public Map<String, String> resolve(AccessRule accessRule, AccessRuleConnection accessRuleConnection, String sessionUuid) {
      Map<String, String> configParameters = new HashMap<>();
      Connection connection = accessRuleConnection.getConnection();
      Bridge bridge = accessRule.getBridge();
      this.setHostParameters(configParameters, connection.getIpAddress(), connection.getPort());
      this.setAuthenticationParameters(configParameters, accessRuleConnection.getCredential());
      this.setConnectionTypeSpecificParameters(configParameters, connection);
      RdpConnectionRemoteApplication rdpConnectionRemoteApplication = accessRuleConnection.getRdpConnectionRemoteApplication();
      if (rdpConnectionRemoteApplication != null) {
         configParameters.put("remote-app", String.format("||%s", rdpConnectionRemoteApplication.getName()));
         configParameters.put("remote-app-dir", rdpConnectionRemoteApplication.getWorkingDirectory());
         configParameters.put("remote-app-args", rdpConnectionRemoteApplication.getParams());
      }

      if (!accessRule.getFileTransferMode().equals(FileTransferMode.NONE)) {
         if (connection.getType().equals(ConnectionType.RDP)) {
            this.setFileTransferParametersForRdpConnection(configParameters, sessionUuid, bridge);
         } else if (connection.getType().equals(ConnectionType.SSH)) {
            this.setFileTransferParametersForSshConnection(configParameters);
         }
      }

      if (!accessRule.isCaptureDisabled()) {
         this.setRecordingParameters(configParameters, accessRule.getUuid(), bridge, sessionUuid);
      }

      return configParameters;
   }

   private void setHostParameters(Map<String, String> parameters, String host, int port) {
      parameters.put("hostname", host);
      parameters.put("port", String.valueOf(port));
   }

   private void setAuthenticationParameters(Map<String, String> parameters, Credential credential) {
      switch (credential.getType()) {
         case USERNAME_PASSWORD:
            UsernamePasswordCredential usernamePasswordCredential = (UsernamePasswordCredential)credential;
            parameters.put("username", usernamePasswordCredential.getUsername());
            parameters.put("password", usernamePasswordCredential.getPassword());
            break;
         case DOMAIN:
            DomainCredential domainCredential = (DomainCredential)credential;
            parameters.put("username", domainCredential.getUsername());
            parameters.put("password", domainCredential.getPassword());
            parameters.put("domain", domainCredential.getDomain());
            break;
         case PRIVATE_KEY:
            PrivateKeyCredential privateKeyCredential = (PrivateKeyCredential)credential;
            parameters.put("username", privateKeyCredential.getUsername());
            parameters.put("private-key", privateKeyCredential.getPrivateKey());
            parameters.put("passphrase", privateKeyCredential.getPassphrase());
      }
   }

   private void setConnectionTypeSpecificParameters(Map<String, String> parameters, Connection connection) {
      switch (connection.getType()) {
         case SSH:
            SshConnection sshConnection = this.fetchTypeSpecificConnection(SshConnection.class, connection.getId());
            parameters.put("color-scheme", sshConnection.getColorScheme().getAsParameterName());
            parameters.put("font-name", sshConnection.getFontName());
            parameters.put("font-size", String.valueOf(sshConnection.getFontSize()));
            break;
         case RDP:
            RdpConnection rdpConnection = this.fetchTypeSpecificConnection(RdpConnection.class, connection.getId());
            parameters.put("security", rdpConnection.getSecurityMode().getAsParameterName());
            parameters.put("ignore-cert", String.valueOf(rdpConnection.isTrustServerCertificate()));
            parameters.put("client-name", rdpConnection.getClientName());
            parameters.put("console", String.valueOf(rdpConnection.isAttachConsole()));
            parameters.put("server-layout", rdpConnection.getKeyboardLayout());
            parameters.put("color-depth", String.valueOf(rdpConnection.getColorDepth().getAsInteger()));
            parameters.put("enable-wallpaper", String.valueOf(rdpConnection.isEnableWallpaper()));
            parameters.put("enable-theming", String.valueOf(rdpConnection.isEnableTheme()));
            parameters.put("enable-font-smoothing", String.valueOf(rdpConnection.isEnableFontSmoothing()));
            parameters.put("enable-menu-animations", String.valueOf(rdpConnection.isEnableAnimation()));
            parameters.put("disable-audio", String.valueOf(rdpConnection.isDisableAudio()));
            parameters.put("console-audio", String.valueOf(rdpConnection.isEnableConsoleAudio()));
            parameters.put("enable-printing", String.valueOf(rdpConnection.isEnablePrinting()));
            parameters.put("printer-name", rdpConnection.getPrinterName());
            parameters.put("enable-audio-input", String.valueOf(rdpConnection.isEnableAudioInput()));
            if (StringUtils.hasContent(rdpConnection.getStartupAppName())) {
               parameters.put("initial-program", rdpConnection.getStartupAppName());
            }
            break;
         case VNC:
            VncConnection vncConnection = this.fetchTypeSpecificConnection(VncConnection.class, connection.getId());
            parameters.put("color-depth", String.valueOf(vncConnection.getColorDepth().getAsInteger()));
            parameters.put("swap-red-blue", String.valueOf(vncConnection.isSwapRedBlue()));
            parameters.put("cursor", vncConnection.getCursorMode().toString().toLowerCase());
            parameters.put("read-only", String.valueOf(vncConnection.isReadOnly()));
            parameters.put("clipboard-encoding", vncConnection.getClipboardEncoding().getAsParameterName());
            if (StringUtils.hasContent(vncConnection.getRepeaterHost())) {
               parameters.put("dest-host", vncConnection.getRepeaterHost());
               parameters.put("dest-port", String.valueOf(vncConnection.getRepeaterPort()));
            }
            break;
         case TELNET:
            TelnetConnection telnetConnection = this.fetchTypeSpecificConnection(TelnetConnection.class, connection.getId());
            parameters.put("color-scheme", telnetConnection.getColorScheme().getAsParameterName());
            parameters.put("font-size", String.valueOf(telnetConnection.getFontSize()));
            parameters.put("font-name", telnetConnection.getFontName());
            parameters.put("password-regex", telnetConnection.getPasswordRegex());
      }
   }

   private void setFileTransferParametersForRdpConnection(Map<String, String> parameters, String sessionUuid, Bridge bridge) {
      parameters.put("enable-drive", String.valueOf(true));
      parameters.put("drive-path", String.format("%s/%s", bridge.getRdpVirtualDriveStoragePath(), sessionUuid));
      parameters.put("drive-name", "Virtual Driver");
      parameters.put("create-drive-path", String.valueOf(true));
   }

   private void setFileTransferParametersForSshConnection(Map<String, String> parameters) {
      parameters.put("enable-sftp", String.valueOf(true));
      parameters.put("sftp-root-directory", "/");
   }

   private void setRecordingParameters(Map<String, String> parameters, String accessRuleUuid, Bridge bridge, String sessionUuid) {
      parameters.put("recording-path", String.format("%s/%s", bridge.getRecordsStoragePath(), accessRuleUuid));
      parameters.put("create-recording-path", String.valueOf(true));
      parameters.put("recording-name", sessionUuid);
      parameters.put("recording-include-keys", String.valueOf(false));
   }

   private <D> D fetchTypeSpecificConnection(Class<D> connectionClass, Long id) {
      return (D)this.nativeQueryBasedReadRepository
         .findOne(new NativeQueryBuilder().from(connectionClass, "c").where(QueryAndFilterUtils.idFilter(id)).build());
   }
}
