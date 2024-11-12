CREATE TABLE IF NOT EXISTS `tb_resource_access_info`
(
    `id`                          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `label`                       VARCHAR(48)     NOT NULL,
    `username`                    VARCHAR(255) DEFAULT NULL,
    `password`                    VARCHAR(255) DEFAULT NULL,
    `secret_key`                  VARCHAR(255) DEFAULT NULL,
    `edit_shared_info_privileged` BIT(1)       DEFAULT 0,
    `creator`                     VARCHAR(64)     NOT NULL,
    `creation_time`               INT UNSIGNED    NOT NULL,
    `last_modifier`               VARCHAR(64)  DEFAULT NULL,
    `last_modification_time`      INT UNSIGNED DEFAULT 0,
    `description`                 VARCHAR(255) DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_resource_access_info_label_creator` (`label`, `creator`),
    CONSTRAINT `ck_info_provided` CHECK ( (`username` IS NOT NULL AND `username` <> '') OR (`password` IS NOT NULL AND `password` <> '') OR (`secret_key` IS NOT NULL AND `secret_key` <> '') )
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

CREATE TABLE IF NOT EXISTS `tb_resource_access_info_user`
(
    `resource_access_info_id` BIGINT UNSIGNED NOT NULL,
    `user_id`                 BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (`resource_access_info_id`, `user_id`),
    KEY `fk_resource_access_info_user_user_id` (`user_id`),
    CONSTRAINT `fk_resource_access_info_user_rai_id` FOREIGN KEY (`resource_access_info_id`) REFERENCES `tb_resource_access_info` (`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_resource_access_info_user_user_id` FOREIGN KEY (`user_id`) REFERENCES `tb_user` (`id`) ON DELETE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;