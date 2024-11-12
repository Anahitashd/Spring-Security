ALTER TABLE `tb_connection`
DROP CONSTRAINT `ck_connection_transparent_port`,
    ADD CONSTRAINT `ck_connection_transparent_port` CHECK ( `transparent_port` >= 50000 AND `transparent_port` <= 51000);