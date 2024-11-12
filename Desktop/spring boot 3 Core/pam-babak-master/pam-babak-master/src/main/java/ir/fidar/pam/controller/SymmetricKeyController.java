package ir.fidar.pam.controller;

import ir.fidar.core.management.response.Response;
import ir.fidar.pam.domain.dto.SymmetricKeyRegisterDto;
import ir.fidar.pam.exception.SymmetricKeyAlreadyRegisteredException;
import ir.fidar.pam.service.SymmetricKeyService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping({"/api/settings/symmetric-key"})
public class SymmetricKeyController {
   private final SymmetricKeyService symmetricKeyService;

   public SymmetricKeyController(SymmetricKeyService symmetricKeyService) {
      this.symmetricKeyService = symmetricKeyService;
   }

   @GetMapping
   public ResponseEntity<Response> getKey() {
      return ResponseEntity.ok(Response.Crud.get(this.symmetricKeyService.load()));
   }

   @PostMapping
   public ResponseEntity<Response> registerKey(@RequestBody @Valid SymmetricKeyRegisterDto registerDto) throws SymmetricKeyAlreadyRegisteredException {
      this.symmetricKeyService.register(registerDto);
      return ResponseEntity.ok(Response.Crud.create());
   }
}
