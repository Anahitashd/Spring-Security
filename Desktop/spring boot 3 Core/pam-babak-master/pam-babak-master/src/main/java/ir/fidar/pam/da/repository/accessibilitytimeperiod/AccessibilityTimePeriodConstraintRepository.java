package ir.fidar.pam.da.repository.accessibilitytimeperiod;

import ir.fidar.pam.domain.model.accessibilitytimeperiod.AccessibilityTimePeriodConstraint;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AccessibilityTimePeriodConstraintRepository extends JpaRepository<AccessibilityTimePeriodConstraint, Long> {
   AccessibilityTimePeriodConstraint findOneByConnectionId(Long var1);

   AccessibilityTimePeriodConstraint findOneByAccessRuleId(Long var1);

   void deleteByConnectionId(Long var1);

   void deleteByAccessRuleId(Long var1);
}
