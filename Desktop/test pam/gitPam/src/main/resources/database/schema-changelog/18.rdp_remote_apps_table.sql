CREATE TABLE IF NOT EXISTS `tb_rdp_connection_remote_application`
(
    `id`                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `name`              VARCHAR(64)     NOT NULL,
    `working_directory` VARCHAR(255) DEFAULT NULL,
    `params`            VARCHAR(255) DEFAULT NULL,
    `connection_id`     BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_rdp_remote_application_name_connection_id` (`name`, `connection_id`),
    KEY `fk_rdp_remote_application_connection_id` (`connection_id`),
    CONSTRAINT `fk_rdp_remote_application_connection_id` FOREIGN KEY (`connection_id`) REFERENCES `tb_connection` (`id`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

ALTER TABLE `tb_access_rule`
    ADD COLUMN `rdp_remote_application_id` BIGINT UNSIGNED DEFAULT NULL,
    ADD FOREIGN KEY `fk_access_rule_rdp_remote_app_id` (`rdp_remote_application_id`) REFERENCES `tb_rdp_connection_remote_application` (id) ON DELETE SET NULL ON UPDATE CASCADE;


INSERT INTO `tb_rdp_connection_remote_application` (`name`, `working_directory`, `params`, `connection_id`)
SELECT remote_app_name, remote_app_params, remote_app_working_directory, id
FROM `tb_rdp_connection`
WHERE remote_app_name IS NOT NULL;

UPDATE `tb_access_rule` ar INNER JOIN `tb_connection` c ON ar.connection_id = c.id
    INNER JOIN `tb_rdp_connection_remote_application` rcra ON c.id = rcra.connection_id
SET ar.rdp_remote_application_id = rcra.id;


ALTER TABLE `tb_rdp_connection`
    DROP COLUMN `remote_app_name`,
    DROP COLUMN `remote_app_params`,
    DROP COLUMN `remote_app_working_directory`;
