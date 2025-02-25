package ir.fidar.pam.session.inputextraction.processor.common;

import ir.fidar.core.util.StringUtils;
import ir.fidar.pam.domain.model.connection.Connection;
import ir.fidar.pam.management.Markers;
import ir.fidar.pam.session.inputextraction.model.ClipboardInfo;
import ir.fidar.pam.session.inputextraction.model.InputSource;
import ir.fidar.pam.session.inputextraction.model.RemoteSessionInputExtraction;
import ir.fidar.pam.session.inputextraction.model.consoletype.ConsoleTypeRemoteSessionInputExtraction;
import ir.fidar.pam.session.inputextraction.model.consoletype.ConsoleTypeRemoteSessionInputProcessingStatus;
import ir.fidar.pam.session.inputextraction.processor.AbstractCommonSessionTypeInstructionProcessor;
import ir.fidar.pam.session.inputextraction.processor.extractor.InputExtractor;
import ir.fidar.pam.session.inputextraction.processor.extractor.common.ClipboardContentExtractor;
import java.util.regex.Pattern;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ClipboardContentProcessor extends AbstractCommonSessionTypeInstructionProcessor<String> {
   private static final Logger LOGGER = LogManager.getLogger();
   private static final String SPECIAL = "(!|&excl;|&#x00021;|&#33;)|(&|&amp;|&AMP;|&#x00026;|&#38;)|(<|&lt;|&LT;|&#x0003C;|&#60;)|(>|&gt;|&GT;|&#x0003E;|&#62;)|(/|&sol;|&#x0002F;|&#47;)|(\\?|&quest;|&#x0003F;|&#63;)|(%|&percnt;|&#x00025;|&#37;)|('|&apos;|&#x00026;|&#38;)|(\"|&quot;|&#x00022;|&#34;)";
   private static final String REGEX = "([#$^*()+=,:;\\\\\\[\\]{}~]|(!|&excl;|&#x00021;|&#33;)|(&|&amp;|&AMP;|&#x00026;|&#38;)|(<|&lt;|&LT;|&#x0003C;|&#60;)|(>|&gt;|&GT;|&#x0003E;|&#62;)|(/|&sol;|&#x0002F;|&#47;)|(\\?|&quest;|&#x0003F;|&#63;)|(%|&percnt;|&#x00025;|&#37;)|('|&apos;|&#x00026;|&#38;)|(\"|&quot;|&#x00022;|&#34;))";
   private static final Pattern PATTERN = Pattern.compile(
      "([#$^*()+=,:;\\\\\\[\\]{}~]|(!|&excl;|&#x00021;|&#33;)|(&|&amp;|&AMP;|&#x00026;|&#38;)|(<|&lt;|&LT;|&#x0003C;|&#60;)|(>|&gt;|&GT;|&#x0003E;|&#62;)|(/|&sol;|&#x0002F;|&#47;)|(\\?|&quest;|&#x0003F;|&#63;)|(%|&percnt;|&#x00025;|&#37;)|('|&apos;|&#x00026;|&#38;)|(\"|&quot;|&#x00022;|&#34;))"
   );

   @Override
   protected InputExtractor<String> getExtractor() {
      return new ClipboardContentExtractor();
   }

   protected void processExtractedInput(String clipboardContent, InputSource source, RemoteSessionInputExtraction remoteSessionInputExtraction) {
      InputSource target = source.equals(InputSource.CLIENT) ? InputSource.SERVER : InputSource.CLIENT;
      Connection connection = remoteSessionInputExtraction.getManagedSession().getConnection();

      try {
         String content = PATTERN.matcher(clipboardContent).replaceAll("");
         remoteSessionInputExtraction.saveClipboard(new ClipboardInfo(content, source, (int)remoteSessionInputExtraction.getElapsedTime()));
         LOGGER.info(
            Markers.SESSION,
            "Clipboard content is transmitted from {} to {} in {} session to server '{}:{}' over access-rule '{}'. Content: {}",
            source.toString().toLowerCase(),
            target.toString().toLowerCase(),
            connection.getType().toString(),
            connection.getIpAddress(),
            connection.getPort(),
            remoteSessionInputExtraction.getManagedSession().getAccessRule().getName(),
            clipboardContent
         );
         if (remoteSessionInputExtraction instanceof ConsoleTypeRemoteSessionInputExtraction && StringUtils.hasContent(content)) {
            ((ConsoleTypeRemoteSessionInputExtraction)remoteSessionInputExtraction).setLastTransmittedClipboard(content);
         }

         remoteSessionInputExtraction.setInputStatus(ConsoleTypeRemoteSessionInputProcessingStatus.NONE);
      } catch (Exception var7) {
         LOGGER.error(
            Markers.SESSION,
            "Unexpected error occurred on processing transmitted clipboard from {} to {} over {} session to '{}:{}'. Session-ID: {}",
            source.toString().toLowerCase(),
            target.toString().toLowerCase(),
            connection.getType().toString(),
            connection.getIpAddress(),
            connection.getPort(),
            remoteSessionInputExtraction.getManagedSession().getId(),
            var7
         );
      }
   }

   public int getOrder() {
      return 16;
   }
}
