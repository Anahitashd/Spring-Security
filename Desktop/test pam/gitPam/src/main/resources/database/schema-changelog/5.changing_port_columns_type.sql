ALTER TABLE `tb_bridge`
    CHANGE COLUMN `port` `port` MEDIUMINT NOT NULL CHECK ( `port` >= 1 AND `port` <= 65535 );

ALTER TABLE `tb_connection`
    CHANGE COLUMN `port` `port` MEDIUMINT NOT NULL CHECK ( `port` >= 1 AND `port` <= 65535 );

ALTER TABLE `tb_vnc_connection`
    CHANGE COLUMN `repeater_port` `repeater_port` MEDIUMINT NOT NULL CHECK ( `repeater_port` >= 1 AND `repeater_port` <= 65535 );

ALTER TABLE `tb_capture`
    CHANGE COLUMN `connection_port` `connection_port` MEDIUMINT NOT NULL CHECK ( `connection_port` >= 1 AND `connection_port` <= 65535 );