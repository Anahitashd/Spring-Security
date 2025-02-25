CREATE TABLE IF NOT EXISTS `tb_session_scanning_transferred_file`
(
    `id`            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `uuid`          VARCHAR(48)     NOT NULL,
    `file_name`     VARCHAR(255)    NOT NULL,
    `multi_av_scanner_record_id` BIGINT UNSIGNED NOT NULL CHECK ( `multi_av_scanner_record_id` >= 0 ),
    `capture_id`    BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_session_scanning_transferred_file` (`uuid`),
    KEY `fk_sstf_capture_id` (`capture_id`),
    CONSTRAINT `fk_sstf_capture_id` FOREIGN KEY (`capture_id`) REFERENCES `tb_capture` (`id`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

ALTER TABLE `tb_ssh_connection`
    ADD COLUMN `malware_scanning_enabled` BIT(1) DEFAULT 0;
ALTER TABLE `tb_rdp_connection`
    ADD COLUMN `malware_scanning_enabled` BIT(1) DEFAULT 0;