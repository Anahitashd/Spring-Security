package ir.fidar.pam.config;

import ir.fidar.core.da.repository.PrivilegeRepository;
import ir.fidar.core.da.repository.RoleRepository;
import ir.fidar.core.domain.model.management.security.Privilege;
import ir.fidar.core.domain.model.management.security.Role;
import ir.fidar.core.security.context.ApplicationStartupInitializer;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import org.springframework.stereotype.Component;

@Component
public class DefaultRolesConfiguration implements ApplicationStartupInitializer {
   private final RoleRepository roleRepository;
   private final PrivilegeRepository privilegeRepository;

   public DefaultRolesConfiguration(RoleRepository roleRepository, PrivilegeRepository privilegeRepository) {
      this.roleRepository = roleRepository;
      this.privilegeRepository = privilegeRepository;
   }

   @Override
   public void initialize() throws Exception {
      Role userRole = this.roleRepository.findOneByTitleIgnoreCase("USER");
      if (userRole == null) {
         userRole = new Role();
         userRole.setTitle("USER");
         userRole.setDescription("Users that only can establish sessions and edit their profiles");
         Privilege updateOwnProfile = this.privilegeRepository.findByName("USER:UPDATE_OWN_PROFILE");
         updateOwnProfile.setName("USER:UPDATE_OWN_PROFILE");
         userRole.setPrivileges(Collections.singleton(updateOwnProfile));
         this.roleRepository.save(userRole);
      }

      Role auditorRole = this.roleRepository.findOneByTitleIgnoreCase("AUDITOR");
      if (auditorRole == null) {
         auditorRole = new Role();
         auditorRole.setTitle("AUDITOR");
         auditorRole.setDescription("Users that only can establish sessions, edit their profiles and audit captures");
         Privilege readCaptures = this.privilegeRepository.findByName("CAPTURE:READ");
         Privilege updateOwnProfile = this.privilegeRepository.findByName("USER:UPDATE_OWN_PROFILE");
         Set<Privilege> privileges = new HashSet<>();
         privileges.add(readCaptures);
         privileges.add(updateOwnProfile);
         auditorRole.setPrivileges(privileges);
         this.roleRepository.save(auditorRole);
      }
   }
}
