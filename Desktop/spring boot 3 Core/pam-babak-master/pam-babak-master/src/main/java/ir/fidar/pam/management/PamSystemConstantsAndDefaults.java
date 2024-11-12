package ir.fidar.pam.management;

import ir.fidar.core.management.SystemConstantsAndDefaults;

public class PamSystemConstantsAndDefaults extends SystemConstantsAndDefaults {
   public static final String BASE_PACKAGE = "ir.fidar.pam";
   public static final String CONTROLLER_BASE_PACKAGE = String.format("%s.%s", "ir.fidar.pam", "controller");
   public static final String DOMAIN_BASE_PACKAGE = String.format("%s.%s", "ir.fidar.pam", "domain");
   public static final String DOMAIN_ENTITY_BASE_PACKAGE = String.format("%s.%s", DOMAIN_BASE_PACKAGE, "model");
}
