package ir.fidar.pam.da.repository.accessibilitytimeperiod;

import ir.fidar.pam.domain.model.accessibilitytimeperiod.MonthlyAccessibilityTimePeriodConstraint;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface MonthlyAccessibilityTimePeriodConstraintRepository extends JpaRepository<MonthlyAccessibilityTimePeriodConstraint, Long> {
   List<MonthlyAccessibilityTimePeriodConstraint> findAllByTimePeriodConstraintId(Long var1);

   void deleteAllByTimePeriodConstraintId(Long var1);
}
