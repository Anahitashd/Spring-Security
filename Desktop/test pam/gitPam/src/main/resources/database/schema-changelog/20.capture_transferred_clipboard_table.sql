CREATE TABLE IF NOT EXISTS `tb_capture_transferred_clipboard`
(
    `id`           BIGINT UNSIGNED    NOT NULL AUTO_INCREMENT,
    `content`      VARCHAR(10000)     NOT NULL,
    `time`         INT UNSIGNED       NOT NULL,
    `elapsed_time` MEDIUMINT UNSIGNED NOT NULL,
    `source`       TINYINT            NOT NULL,
    `capture_id`   BIGINT UNSIGNED    NOT NULL,

    PRIMARY KEY (`id`),
    CONSTRAINT `fk_capture_transferred_clipboard_capture_id` FOREIGN KEY (`capture_id`) REFERENCES `tb_capture` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT `ck_capture_transferred_clipboard_time` CHECK ( `time` > 0 AND `time` < 4000000000 ),
    CONSTRAINT `ck_capture_transferred_clipboard_elapsed_time` CHECK ( `elapsed_time` > 0 )
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;