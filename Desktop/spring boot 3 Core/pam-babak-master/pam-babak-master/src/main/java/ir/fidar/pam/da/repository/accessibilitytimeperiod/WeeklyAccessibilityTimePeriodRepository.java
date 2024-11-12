package ir.fidar.pam.da.repository.accessibilitytimeperiod;

import ir.fidar.pam.domain.model.accessibilitytimeperiod.WeeklyAccessibilityTimePeriodConstraint;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface WeeklyAccessibilityTimePeriodRepository extends JpaRepository<WeeklyAccessibilityTimePeriodConstraint, Long> {
   List<WeeklyAccessibilityTimePeriodConstraint> findAllByTimePeriodConstraintId(Long var1);

   void deleteAllByTimePeriodConstraintId(Long var1);
}
