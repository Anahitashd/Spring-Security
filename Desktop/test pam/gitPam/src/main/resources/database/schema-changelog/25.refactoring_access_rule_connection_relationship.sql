CREATE TABLE IF NOT EXISTS `tb_access_rule_connection`
(
    `access_rule_id`            BIGINT UNSIGNED NOT NULL,
    `connection_id`             BIGINT UNSIGNED NOT NULL,
    `credential_id`             BIGINT UNSIGNED DEFAULT NULL,
    `rdp_remote_application_id` BIGINT UNSIGNED DEFAULT NULL,

    PRIMARY KEY (`access_rule_id`, `connection_id`),
    KEY `fk_access_rule_connection_access_rule_id` (`access_rule_id`),
    KEY `fk_access_rule_connection_connection_id` (`connection_id`),
    CONSTRAINT `fk_access_rule_connection_access_rule_id`
        FOREIGN KEY `fk_access_rule_connection_access_rule_id` (`access_rule_id`)
            REFERENCES `tb_access_rule` (`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_access_rule_connection_connection_id`
        FOREIGN KEY `fk_access_rule_connection_connection_id` (`connection_id`)
            REFERENCES `tb_connection` (`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_access_rule_connection_credential_id`
        FOREIGN KEY `fk_access_rule_connection_credential_id` (`credential_id`)
            REFERENCES `tb_credential` (id) ON DELETE SET NULL ON UPDATE CASCADE,
    CONSTRAINT `fk_access_rule_connection_rdp_remote_app_id`
        FOREIGN KEY `fk_access_rule_connection_rdp_remote_app_id` (`rdp_remote_application_id`)
            REFERENCES `tb_rdp_connection_remote_application` (id) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;


CREATE TABLE IF NOT EXISTS `tb_access_rule_connection_group`
(
    `access_rule_id`      BIGINT UNSIGNED NOT NULL,
    `connection_group_id` BIGINT UNSIGNED NOT NULL,

    PRIMARY KEY (`access_rule_id`, connection_group_id),
    KEY `fk_access_rule_connection_group_access_rule_id` (`access_rule_id`),
    KEY `fk_access_rule_connection_group_cg_id` (connection_group_id),
    CONSTRAINT `fk_access_rule_connection_group_access_rule_id`
        FOREIGN KEY `fk_access_rule_connection_group_access_rule_id` (`access_rule_id`)
            REFERENCES `tb_access_rule` (`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_access_rule_connection_group_cg_id`
        FOREIGN KEY `fk_access_rule_connection_group_cg_id` (connection_group_id)
            REFERENCES `tb_connection_group` (`id`) ON DELETE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

INSERT INTO `tb_access_rule_connection` (`access_rule_id`, `connection_id`, `credential_id`, `rdp_remote_application_id`)
SELECT ar.id, ar.connection_id, c.id, ar.rdp_remote_application_id
FROM tb_access_rule ar
    LEFT JOIN tb_credential c ON ar.id = c.access_rule_id;

ALTER TABLE tb_access_rule
    DROP KEY `fk_access_rule_connection_id`,
    DROP CONSTRAINT `fk_access_rule_connection_id`,
    DROP COLUMN `connection_id`;

ALTER TABLE tb_credential
    DROP KEY `uk_credential_access_rule_id`,
    DROP CONSTRAINT `fk_credential_access_rule_id`,
    DROP COLUMN `access_rule_id`;
