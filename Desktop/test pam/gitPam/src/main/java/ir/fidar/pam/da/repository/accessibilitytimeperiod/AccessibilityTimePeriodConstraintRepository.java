package ir.fidar.pam.da.repository.accessibilitytimeperiod;

import ir.fidar.pam.domain.model.accessibilitytimeperiod.AccessibilityTimePeriodConstraint;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AccessibilityTimePeriodConstraintRepository extends JpaRepository<AccessibilityTimePeriodConstraint, Long> {
   AccessibilityTimePeriodConstraint findOneByConnectionId(Long var1);

   AccessibilityTimePeriodConstraint findOneByAccessRuleId(Long var1);

   void deleteByConnectionId(Long var1);

   void deleteByAccessRuleId(Long var1);

   @Query("SELECT atpc FROM AccessibilityTimePeriodConstraint atpc LEFT JOIN FETCH atpc.accessRule ar LEFT JOIN FETCH atpc.connection c " +
           "LEFT JOIN FETCH atpc.dailyConstraint dc " +
           " WHERE (ar.id = :accessRuleId OR c.id = :connectionId)")
   List<AccessibilityTimePeriodConstraint> fetchAccessibilityTimePeriodConstraints(@Param("accessRuleId") Long accessRuleId, @Param("connectionId") Long connectionId);
}
