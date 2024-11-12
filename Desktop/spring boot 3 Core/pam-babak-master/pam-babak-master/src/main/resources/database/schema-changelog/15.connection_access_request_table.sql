CREATE TABLE IF NOT EXISTS `tb_connection_access_request`
(
    `id`                 BIGINT UNSIGNED   NOT NULL AUTO_INCREMENT,
    `identifier`         VARCHAR(48)       NOT NULL,
    `ip_address`         VARCHAR(48)       NOT NULL,
    `port`               SMALLINT UNSIGNED NOT NULL CHECK ( `port` >= 1 AND `port` <= 65535 ),
    `type`               TINYINT           NOT NULL,
    `clipboard_enabled`  BIT(1)            NOT NULL,
    `file_transfer_mode` TINYINT           NOT NULL,
    `status`             TINYINT           NOT NULL,
    `admin_review_note`  VARCHAR(255) DEFAULT NULL,
    `application_time`   INT UNSIGNED      NOT NULL CHECK ( `application_time` > 0 ),
    `description`        VARCHAR(255) DEFAULT NULL,
    `user_id`            BIGINT UNSIGNED   NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_connection_request_access_identifier` (`identifier`),
    KEY `fk_connection_request_access_user_id` (`user_id`),
    CONSTRAINT `fk_connection_request_access_user_id` FOREIGN KEY (`user_id`) REFERENCES `tb_user` (`id`) ON DELETE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;