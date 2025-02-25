CREATE TABLE IF NOT EXISTS `tb_database_schema_version`
(
    `version`          VARCHAR(16)  NOT NULL,
    `mode`             VARCHAR(16)  NOT NULL,
    `script_file_name` VARCHAR(128) NOT NULL,
    `description`      VARCHAR(255) DEFAULT NULL,
    `date`             VARCHAR(32)  NOT NULL
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;