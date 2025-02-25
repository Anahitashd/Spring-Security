CREATE TABLE IF NOT EXISTS `tb_capture_client_information`
(
    `id`            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `screen_width`  SMALLINT        NOT NULL,
    `screen_height` SMALLINT        NOT NULL,
    `screen_dpi`    SMALLINT        NOT NULL,
    PRIMARY KEY (`id`),
    CONSTRAINT `fk_capture_client_information_id` FOREIGN KEY (`id`) REFERENCES `tb_capture` (`id`) ON DELETE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;