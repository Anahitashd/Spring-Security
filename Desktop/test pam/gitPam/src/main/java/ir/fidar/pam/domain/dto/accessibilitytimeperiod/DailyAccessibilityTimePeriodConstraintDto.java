package ir.fidar.pam.domain.dto.accessibilitytimeperiod;

public class DailyAccessibilityTimePeriodConstraintDto {
   private Integer fromHour;
   private Integer fromMinute;
   private Integer toHour;
   private Integer toMinute;

   public Integer getFromHour() {
      return this.fromHour;
   }

   public void setFromHour(Integer fromHour) {
      this.fromHour = fromHour;
   }

   public Integer getFromMinute() {
      return this.fromMinute;
   }

   public void setFromMinute(Integer fromMinute) {
      this.fromMinute = fromMinute;
   }

   public Integer getToHour() {
      return this.toHour;
   }

   public void setToHour(Integer toHour) {
      this.toHour = toHour;
   }

   public Integer getToMinute() {
      return this.toMinute;
   }

   public void setToMinute(Integer toMinute) {
      this.toMinute = toMinute;
   }
}
