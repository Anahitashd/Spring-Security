package ir.fidar.pam.domain.dto.batchcommand;

import java.util.List;

public class BatchCommandResultDto {
   private String label;
   private List<String> results;

   public String getLabel() {
      return this.label;
   }

   public void setLabel(String label) {
      this.label = label;
   }

   public List<String> getResults() {
      return this.results;
   }

   public void setResults(List<String> results) {
      this.results = results;
   }
}
