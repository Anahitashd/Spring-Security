ALTER TABLE `tb_credential` DROP INDEX `uk_credential_label`;
ALTER TABLE `tb_credential` ADD CONSTRAINT `uk_credential_label_connection_id` UNIQUE KEY (`label`, `connection_id`);