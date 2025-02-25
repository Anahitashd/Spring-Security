package ir.fidar.pam.domain.model.accessibilitytimeperiod;

import ir.fidar.core.domain.model.BaseEntity;
import ir.fidar.core.security.validation.CustomizedXssProtected;
import ir.fidar.pam.domain.model.accessrule.AccessRule;
import ir.fidar.pam.domain.model.connection.Connection;
import ir.fidar.pam.domain.type.AccessibilityTimePeriodMode;
import ir.fidar.pam.domain.util.converter.attribbute.AccessibilityTimePeriodModeConverter;
import org.hibernate.annotations.Fetch;
import org.hibernate.annotations.FetchMode;

import java.util.List;
import javax.persistence.CascadeType;
import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.OneToMany;
import javax.persistence.OneToOne;
import javax.persistence.Table;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;

@Entity
@Table(
   name = "tb_accessibility_time_period"
)
public class AccessibilityTimePeriodConstraint extends BaseEntity {
   @NotNull(
      message = "null.mode"
   )
   @Convert(
      converter = AccessibilityTimePeriodModeConverter.class
   )
   private AccessibilityTimePeriodMode mode;
   @NotBlank(
      message = "blank.timezone"
   )
   @Pattern(
      regexp = "(UTC|GMT|UT|Z)|([A-Za-z][A-Za-z0-9~/._+-]+)",
      message = "wrng_pattern.timezone"
   )
   @Size(
      max = 64,
      message = "gt_max.timezone"
   )
   @CustomizedXssProtected(
      skippingCharacters = {'/'}
   )
   private String timezone;
   @OneToOne(
      mappedBy = "timePeriodConstraint",
      fetch = FetchType.LAZY,
      cascade = {CascadeType.ALL}
   )
   private DailyAccessibilityTimePeriodConstraint dailyConstraint;
   @OneToMany(
      mappedBy = "timePeriodConstraint",
      fetch = FetchType.LAZY,
      cascade = {CascadeType.ALL}
   )
   @Fetch(FetchMode.SUBSELECT)
   private List<WeeklyAccessibilityTimePeriodConstraint> weeklyConstraints;
   @OneToMany(
      mappedBy = "timePeriodConstraint",
      fetch = FetchType.LAZY,
      cascade = {CascadeType.ALL}
   )
   @Fetch(FetchMode.SUBSELECT)
   private List<MonthlyAccessibilityTimePeriodConstraint> monthlyConstraints;
   @OneToOne(
      fetch = FetchType.LAZY
   )
   @JoinColumn(
      name = "connection_id"
   )
   private Connection connection;
   @OneToOne(
      fetch = FetchType.LAZY
   )
   @JoinColumn(
      name = "access_rule_id"
   )
   private AccessRule accessRule;

   public AccessibilityTimePeriodMode getMode() {
      return this.mode;
   }

   public void setMode(AccessibilityTimePeriodMode mode) {
      this.mode = mode;
   }

   public String getTimezone() {
      return this.timezone;
   }

   public void setTimezone(String timezone) {
      this.timezone = timezone;
   }

   public DailyAccessibilityTimePeriodConstraint getDailyConstraint() {
      return this.dailyConstraint;
   }

   public void setDailyConstraint(DailyAccessibilityTimePeriodConstraint dailyConstraint) {
      this.dailyConstraint = dailyConstraint;
   }

   public List<WeeklyAccessibilityTimePeriodConstraint> getWeeklyConstraints() {
      return this.weeklyConstraints;
   }

   public void setWeeklyConstraints(List<WeeklyAccessibilityTimePeriodConstraint> weekDays) {
      this.weeklyConstraints = weekDays;
   }

   public List<MonthlyAccessibilityTimePeriodConstraint> getMonthlyConstraints() {
      return this.monthlyConstraints;
   }

   public void setMonthlyConstraints(List<MonthlyAccessibilityTimePeriodConstraint> monthDays) {
      this.monthlyConstraints = monthDays;
   }

   public Connection getConnection() {
      return this.connection;
   }

   public void setConnection(Connection connection) {
      this.connection = connection;
   }

   public AccessRule getAccessRule() {
      return this.accessRule;
   }

   public void setAccessRule(AccessRule accessRules) {
      this.accessRule = accessRules;
   }
}
