CREATE TABLE IF NOT EXISTS `tb_transparent_capture`
(
    `id`                      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `session_id`              VARCHAR(48)     NOT NULL,
    `status`                  TINYINT         NOT NULL,
    `start_time`              INT             NOT NULL CHECK ( `start_time` > 0 ),
    `end_time`                INT             NOT NULL CHECK ( `end_time` >= 0 ),
    `connection_type`         TINYINT         NOT NULL,
    `connection_name`         VARCHAR(48)     NOT NULL,
    `connection_ip_address`   VARCHAR(48)     NOT NULL,
    `connection_port`         INT             NOT NULL CHECK ( `connection_port` >= 1 AND `connection_port` <= 65535),
    `client_ip_address`       VARCHAR(48)     NOT NULL,
    `client_port`             INT          DEFAULT NULL CHECK (`client_port` >= 0 AND `client_port` <= 65535),
    `client_username`         VARCHAR(64)  DEFAULT NULL,
    `client_password`         VARCHAR(128) DEFAULT NULL,
    `client_domain`           VARCHAR(64)  DEFAULT NULL,
    `client_hostname`         VARCHAR(64)  DEFAULT NULL,
    `client_certificate_name` VARCHAR(64)  DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_transparent_capture_session_id` (`session_id`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

ALTER TABLE `tb_capture`
    DROP COLUMN `transparent`;

ALTER TABLE `tb_rdp_connection`
    DROP CONSTRAINT `uk_rdp_connection_transparent_port`,
    DROP COLUMN transparent_port;

ALTER TABLE `tb_connection`
    ADD COLUMN `transparent_port` SMALLINT UNSIGNED DEFAULT NULL,
    ADD CONSTRAINT `ck_connection_transparent_port` CHECK ( `transparent_port` >= 50000 AND `transparent_port` <= 50200);