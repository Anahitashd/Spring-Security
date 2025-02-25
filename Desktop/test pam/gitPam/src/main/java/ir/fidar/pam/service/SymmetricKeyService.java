package ir.fidar.pam.service;

import ir.fidar.pam.domain.dto.SymmetricKeyDto;
import ir.fidar.pam.domain.dto.SymmetricKeyRegisterDto;
import ir.fidar.pam.exception.SymmetricKeyAlreadyRegisteredException;
import java.util.Optional;

public interface SymmetricKeyService {
   Optional<SymmetricKeyDto> load();

   void register(SymmetricKeyRegisterDto var1) throws SymmetricKeyAlreadyRegisteredException;
}
