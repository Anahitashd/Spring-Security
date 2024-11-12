package ir.fidar.pam.da.repository.accessibilitytimeperiod;

import ir.fidar.pam.domain.model.accessibilitytimeperiod.DailyAccessibilityTimePeriodConstraint;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface DailyAccessibilityTimePeriodConstraintRepository extends JpaRepository<DailyAccessibilityTimePeriodConstraint, Long> {
   DailyAccessibilityTimePeriodConstraint findOneByTimePeriodConstraintId(Long var1);

   void deleteByTimePeriodConstraintId(Long var1);
}
