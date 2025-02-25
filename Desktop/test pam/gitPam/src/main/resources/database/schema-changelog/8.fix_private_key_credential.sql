DELETE FROM `tb_private_key_credential`;
DELETE FROM `tb_credential` WHERE `type`=3;
ALTER TABLE `tb_private_key_credential` ADD COLUMN `username` VARCHAR(255) NOT NULL FIRST;