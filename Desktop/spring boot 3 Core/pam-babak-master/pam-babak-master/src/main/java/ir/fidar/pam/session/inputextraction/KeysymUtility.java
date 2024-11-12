package ir.fidar.pam.session.inputextraction;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.module.SimpleModule;
import ir.fidar.core.exception.api.ServerTerminationException;
import ir.fidar.pam.management.Markers;
import ir.fidar.pam.session.inputextraction.model.KeyType;
import java.io.IOException;
import java.util.Arrays;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

@Component
public class KeysymUtility implements InitializingBean, ApplicationContextAware {
   private static final Logger LOGGER = LogManager.getLogger();
   private ApplicationContext applicationContext;
   private static KeysymUtility.Keysyms KEYSYMS;
   private static Map<String, String> READABLE_NAMES;

   public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
      this.applicationContext = applicationContext;
   }

   public void afterPropertiesSet() throws Exception {
      ObjectMapper objectMapper = new ObjectMapper();
      SimpleModule module = new SimpleModule();
      module.addDeserializer(KeyType.class, new KeysymUtility.KeyInfoStatusDeserializer());
      objectMapper.registerModule(module);

      try {
         Resource resource = new ClassPathResource("remote-session-key-extraction/keysyms.json");
         KEYSYMS = (KeysymUtility.Keysyms)objectMapper.readValue(resource.getInputStream(), KeysymUtility.Keysyms.class);
         resource = new ClassPathResource("remote-session-key-extraction/readable-names.json");
         READABLE_NAMES = (Map<String, String>)objectMapper.readValue(resource.getInputStream(), new TypeReference<Map<String, String>>() {
         });
         LOGGER.debug(Markers.SESSION, "Keysym information is loaded on memory");
      } catch (IOException var4) {
         LOGGER.error(Markers.SESSION, "Unexpected error occurred while loading keysyms on memory. Terminating server", var4);
         throw new ServerTerminationException(var4, this.applicationContext);
      }
   }

   public static KeysymUtility.KeyInfo resolveKey(int keysym) {
      Integer index = KEYSYMS.getKeysyms().get(String.valueOf(keysym));
      return index == null ? null : KEYSYMS.getRecords()[index];
   }

   public static String convertToReadable(String name) {
      return READABLE_NAMES.getOrDefault(name, name);
   }

   public static class KeyInfo {
      private final int keysym;
      private final int unicode;
      private final String[] names;
      @JsonDeserialize(
         using = KeysymUtility.KeyInfoStatusDeserializer.class
      )
      private final KeyType type;

      @Override
      public String toString() {
         return "KeyInfo{keysym="
            + this.keysym
            + ", unicode="
            + this.unicode
            + ", names="
            + Arrays.toString((Object[])this.names)
            + ", type="
            + this.type
            + '}';
      }

      private KeyInfo(
         @JsonProperty("keysym") int keysym, @JsonProperty("unicode") int unicode, @JsonProperty("names") String[] names, @JsonProperty("status") KeyType type
      ) {
         this.keysym = keysym;
         this.unicode = unicode;
         this.names = names;
         this.type = type;
      }

      public int getKeysym() {
         return this.keysym;
      }

      public int getUnicode() {
         return this.unicode;
      }

      public String[] getNames() {
         return this.names;
      }

      public KeyType getType() {
         return this.type;
      }
   }

   public static class KeyInfoStatusDeserializer extends StdDeserializer<KeyType> {
      public KeyInfoStatusDeserializer() {
         this(null);
      }

      protected KeyInfoStatusDeserializer(Class<?> vc) {
         super(vc);
      }

      public KeyType deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException, JsonProcessingException {
         String type = jsonParser.getText();
         switch (type) {
            case ".":
               return KeyType.CHAR;
            case "f":
               return KeyType.FUNC;
            default:
               return KeyType.OTHER;
         }
      }
   }

   private static class Keysyms {
      private final KeysymUtility.KeyInfo[] records;
      private final Map<String, Integer> keysyms;

      private Keysyms(@JsonProperty("records") KeysymUtility.KeyInfo[] records, @JsonProperty("keysyms") Map<String, Integer> keysyms) {
         this.records = records;
         this.keysyms = keysyms;
      }

      public KeysymUtility.KeyInfo[] getRecords() {
         return this.records;
      }

      public Map<String, Integer> getKeysyms() {
         return this.keysyms;
      }
   }
}
