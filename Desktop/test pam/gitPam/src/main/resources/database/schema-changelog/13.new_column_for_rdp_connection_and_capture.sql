ALTER TABLE `tb_rdp_connection`
    ADD COLUMN `transparent_port` SMALLINT UNSIGNED DEFAULT NULL CHECK ( `transparent_port` >= 50001 AND `transparent_port` <= 50005 ),
    ADD UNIQUE KEY `uk_rdp_connection_transparent_port` (`transparent_port`);

ALTER TABLE `tb_capture`
    ADD COLUMN `transparent` BIT(1) DEFAULT 0;