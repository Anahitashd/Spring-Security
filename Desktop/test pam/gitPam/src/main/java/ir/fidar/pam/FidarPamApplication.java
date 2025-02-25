package ir.fidar.pam;

import ir.fidar.core.CoreApplication;
import ir.fidar.core.license.register.EnableLicense;
import ir.fidar.core.management.env.Profile;
import ir.fidar.core.management.log.configuration.LoggerLevelsSystemPropertiesInitializer;
import java.util.Arrays;
import org.springframework.boot.SpringApplication;

@EnableLicense
public class FidarPamApplication {
   public static void main(String[] args) {
      initializeLoggersLevel(args);
      SpringApplication.run(new Class[]{CoreApplication.class}, args);
   }

   private static void initializeLoggersLevel(String[] args) {
      Profile profile = Arrays.asList(args).stream().filter(arg -> arg.contains("spring.profiles.active")).map(arg -> {
         String[] parts = arg.split("=");
         return Profile.valueOf(parts[1].toUpperCase());
      }).findAny().get();
      LoggerLevelsSystemPropertiesInitializer.initialize(profile);
   }
}
