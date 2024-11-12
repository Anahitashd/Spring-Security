package ir.fidar.pam.domain.dto.connection.update;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.JsonSubTypes.Type;
import com.fasterxml.jackson.annotation.JsonTypeInfo.As;
import com.fasterxml.jackson.annotation.JsonTypeInfo.Id;
import ir.fidar.core.domain.dto.crud.UpdateDto;
import ir.fidar.pam.domain.dto.connection.create.ConnectionCreateDto;

@JsonTypeInfo(
   use = Id.NAME,
   include = As.PROPERTY,
   property = "type",
   visible = true
)
@JsonSubTypes({@Type(
      value = SshConnectionUpdateDto.class,
      name = "SSH"
   ), @Type(
      value = RdpConnectionUpdateDto.class,
      name = "RDP"
   ), @Type(
      value = VncConnectionUpdateDto.class,
      name = "VNC"
   ), @Type(
      value = TelnetConnectionUpdateDto.class,
      name = "TELNET"
   )})
public class ConnectionUpdateDto extends ConnectionCreateDto implements UpdateDto {
}
