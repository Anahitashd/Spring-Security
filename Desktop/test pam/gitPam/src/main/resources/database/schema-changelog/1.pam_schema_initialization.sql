--
-- Table structure for table `tb_bridge`
--
CREATE TABLE IF NOT EXISTS `tb_bridge`
(
    `id`                             BIGINT UNSIGNED   NOT NULL AUTO_INCREMENT,
    `name`                           VARCHAR(48)       NOT NULL,
    `ip_address`                     VARCHAR(48)       NOT NULL,
    `port`                           SMALLINT UNSIGNED NOT NULL CHECK ( `port` >= 1 AND `port` <= 65535 ),
    `rdp_virtual_drive_storage_path` VARCHAR(255)      NOT NULL,
    `records_storage_path`           VARCHAR(255)      NOT NULL,
    `creator`                        VARCHAR(64)       NOT NULL,
    `creation_time`                  INT UNSIGNED      NOT NULL,
    `last_modifier`                  VARCHAR(64)  DEFAULT NULL,
    `last_modification_time`         INT UNSIGNED DEFAULT 0,
    `description`                    VARCHAR(255) DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_bridge_name` (`name`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

--
-- Table structure for table `tb_session_input_constraint`
--
CREATE TABLE IF NOT EXISTS `tb_session_input_constraint`
(
    `id`                     BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `name`                   VARCHAR(48)     NOT NULL,
    `regex`                  VARCHAR(255)    NOT NULL,
    `creator`                VARCHAR(64)     NOT NULL,
    `creation_time`          INT UNSIGNED    NOT NULL,
    `last_modifier`          VARCHAR(64)  DEFAULT NULL,
    `last_modification_time` INT UNSIGNED DEFAULT 0,
    `description`            VARCHAR(255) DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_session_input_constraint_name` (`name`),
    UNIQUE KEY `uk_session_input_constraint_regex` (`regex`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

--
-- Table structure for table `tb_connection`
--
CREATE TABLE IF NOT EXISTS `tb_connection`
(
    `id`                                   BIGINT UNSIGNED   NOT NULL AUTO_INCREMENT,
    `name`                                 VARCHAR(48)       NOT NULL,
    `type`                                 TINYINT           NOT NULL,
    `ip_address`                           VARCHAR(48)       NOT NULL,
    `port`                                 SMALLINT UNSIGNED NOT NULL CHECK ( `port` >= 1 AND `port` <= 65535 ),
    `clipboard`                            BIT(1)            NOT NULL,
    `maximum_concurrent_sessions`          INT               NOT NULL DEFAULT 0,
    `maximum_concurrent_sessions_per_user` INT               NOT NULL DEFAULT 0,
    `creator`                              VARCHAR(64)       NOT NULL,
    `creation_time`                        INT UNSIGNED      NOT NULL,
    `last_modifier`                        VARCHAR(64)                DEFAULT NULL,
    `last_modification_time`               INT UNSIGNED               DEFAULT 0,
    `description`                          VARCHAR(255)               DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_connection_type_ip_address_port` (`type`, `ip_address`, `port`),
    UNIQUE KEY `uk_connection_name` (`name`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

--
-- Table structure for table `tb_ssh_connection`
--
CREATE TABLE IF NOT EXISTS `tb_ssh_connection`
(
    `id`                 BIGINT UNSIGNED NOT NULL,
    `file_transfer_mode` TINYINT         NOT NULL,
    `color_scheme`       TINYINT         NOT NULL,
    `font_name`          VARCHAR(64) DEFAULT NULL,
    `font_size`          INT             NOT NULL,
    `bastion`            BIT(1)          NOT NULL,
    PRIMARY KEY (`id`),
    CONSTRAINT `fk_ssh_connection_connection_id` FOREIGN KEY (`id`) REFERENCES `tb_connection` (`id`) ON DELETE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

--
-- Table structure for table `tb_rdp_connection`
--
CREATE TABLE IF NOT EXISTS `tb_rdp_connection`
(
    `id`                           BIGINT UNSIGNED NOT NULL,
    `file_transfer_mode`           TINYINT         NOT NULL,
    `attach_console`               BIT(1)          NOT NULL,
    `client_name`                  VARCHAR(255) DEFAULT NULL,
    `color_depth`                  TINYINT         NOT NULL,
    `disable_audio`                BIT(1)          NOT NULL,
    `enable_animation`             BIT(1)          NOT NULL,
    `enable_console_audio`         BIT(1)          NOT NULL,
    `enable_font_smoothing`        BIT(1)          NOT NULL,
    `enable_printing`              BIT(1)          NOT NULL,
    `enable_theme`                 BIT(1)          NOT NULL,
    `enable_wallpaper`             BIT(1)          NOT NULL,
    `keyboard_layout`              VARCHAR(255) DEFAULT NULL,
    `remote_app_name`              VARCHAR(255) DEFAULT NULL,
    `remote_app_params`            VARCHAR(255) DEFAULT NULL,
    `remote_app_working_directory` VARCHAR(255) DEFAULT NULL,
    `security_mode`                TINYINT         NOT NULL,
    `startup_app_name`             VARCHAR(255) DEFAULT NULL,
    `trust_server_certificate`     BIT(1)          NOT NULL,
    PRIMARY KEY (`id`),
    CONSTRAINT `fk_rdp_connection_connection_id` FOREIGN KEY (`id`) REFERENCES `tb_connection` (`id`) ON DELETE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

--
-- Table structure for table `tb_vnc_connection`
--
CREATE TABLE IF NOT EXISTS `tb_vnc_connection`
(
    `id`                 BIGINT UNSIGNED   NOT NULL,
    `clipboard_encoding` TINYINT           NOT NULL,
    `color_depth`        TINYINT           NOT NULL,
    `cursor_mode`        TINYINT           NOT NULL,
    `read_only`          BIT(1)            NOT NULL,
    `repeater_host`      VARCHAR(48)       NOT NULL,
    `repeater_port`      SMALLINT UNSIGNED NOT NULL CHECK ( `repeater_port` >= 1 AND `repeater_port` <= 65535 ),
    `swap_red_blue`      BIT(1)            NOT NULL,
    PRIMARY KEY (`id`),
    CONSTRAINT `fk_vnc_connection_connection_id` FOREIGN KEY (`id`) REFERENCES `tb_connection` (`id`) ON DELETE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

--
-- Table structure for table `tb_telnet_connection`
--
CREATE TABLE IF NOT EXISTS `tb_telnet_connection`
(
    `id`             BIGINT UNSIGNED NOT NULL,
    `color_scheme`   TINYINT         NOT NULL,
    `font_name`      VARCHAR(64)  DEFAULT NULL,
    `font_size`      INT             NOT NULL,
    `password_regex` VARCHAR(255) DEFAULT NULL,
    `bastion`        BIT(1)          NOT NULL,
    PRIMARY KEY (`id`),
    CONSTRAINT `fk_telnet_connection_connection_id` FOREIGN KEY (`id`) REFERENCES `tb_connection` (`id`) ON DELETE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

--
-- Table structure for table `tb_connection_group`
--
CREATE TABLE IF NOT EXISTS `tb_connection_group`
(
    `id`                     BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `name`                   VARCHAR(48)     NOT NULL,
    `creator`                VARCHAR(64)     NOT NULL,
    `creation_time`          INT UNSIGNED    NOT NULL,
    `last_modifier`          VARCHAR(64)  DEFAULT NULL,
    `last_modification_time` INT UNSIGNED DEFAULT 0,
    `description`            VARCHAR(255) DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_connection_group_name` (`name`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

--
-- Table structure for table `tb_connection_group_connection`
--
CREATE TABLE IF NOT EXISTS `tb_connection_group_connection`
(
    `connection_group_id` BIGINT UNSIGNED NOT NULL,
    `connection_id`       BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (`connection_group_id`, `connection_id`),
    KEY `fk_connection_group_connection_connection_id` (`connection_id`),
    CONSTRAINT `fk_connection_group_connection_connection_id` FOREIGN KEY (`connection_id`) REFERENCES `tb_connection` (`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_connection_group_connection_connection_group_id` FOREIGN KEY (`connection_group_id`) REFERENCES `tb_connection_group` (`id`) ON DELETE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

--
-- Table structure for table `tb_access_rule`
--
CREATE TABLE IF NOT EXISTS `tb_access_rule`
(
    `id`                     BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `name`                   VARCHAR(48)     NOT NULL,
    `uuid`                   VARCHAR(48)     NOT NULL,
    `clipboard`              BIT(1)          NOT NULL,
    `disabled`               BIT(1)          NOT NULL,
    `expiration_time`        INT UNSIGNED DEFAULT 0,
    `file_transfer_mode`     TINYINT         NOT NULL,
    `ocr_enabled`            BIT(1)          NOT NULL,
    `bridge_id`              BIGINT UNSIGNED NOT NULL,
    `connection_id`          BIGINT UNSIGNED NOT NULL,
    `bastion`                BIT(1)          NOT NULL,
    `creator`                VARCHAR(64)     NOT NULL,
    `creation_time`          INT UNSIGNED    NOT NULL,
    `last_modifier`          VARCHAR(64)  DEFAULT NULL,
    `last_modification_time` INT UNSIGNED DEFAULT 0,
    `description`            VARCHAR(255) DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_access_rule_name` (`name`),
    UNIQUE KEY `uk_access_rule_uuid` (`uuid`),
    KEY `fk_access_rule_bridge_id` (`bridge_id`),
    KEY `fk_access_rule_connection_id` (`connection_id`),
    CONSTRAINT `fk_access_rule_bridge_id` FOREIGN KEY (`bridge_id`) REFERENCES `tb_bridge` (`id`),
    CONSTRAINT `fk_access_rule_connection_id` FOREIGN KEY (`connection_id`) REFERENCES `tb_connection` (`id`) ON DELETE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

CREATE TABLE IF NOT EXISTS `tb_access_rule_user`
(
    `access_rule_id` BIGINT UNSIGNED NOT NULL,
    `user_id`        BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (`access_rule_id`, `user_id`),
    KEY `fk_access_rule_user_user_id` (`user_id`),
    CONSTRAINT `fk_access_rule_user_access_rule_id` FOREIGN KEY (`access_rule_id`) REFERENCES `tb_access_rule` (`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_access_rule_user_user_id` FOREIGN KEY (`user_id`) REFERENCES `tb_user` (`id`) ON DELETE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

--
-- Table structure for table `tb_access_rule_user_group`
--
CREATE TABLE IF NOT EXISTS `tb_access_rule_user_group`
(
    `access_rule_id` BIGINT UNSIGNED NOT NULL,
    `user_group_id`  BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (`access_rule_id`, `user_group_id`),
    KEY `fk_access_rule_user_group_user_group_id` (`user_group_id`),
    CONSTRAINT `fk_access_rule_user_group_access_rule_id` FOREIGN KEY (`user_group_id`) REFERENCES `tb_user_group` (`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_access_rule_user_group_user_group_id` FOREIGN KEY (`access_rule_id`) REFERENCES `tb_access_rule` (`id`) ON DELETE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

--
-- Table structure for table `tb_credential`
--
CREATE TABLE IF NOT EXISTS `tb_credential`
(
    `id`             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `label`          VARCHAR(48)     NOT NULL,
    `type`           TINYINT         NOT NULL,
    `access_rule_id` BIGINT UNSIGNED DEFAULT NULL,
    `connection_id`  BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_credential_label` (`label`),
    UNIQUE KEY `uk_credential_access_rule_id` (`access_rule_id`),
    KEY `fk_credential_connection_id` (`connection_id`),
    CONSTRAINT `fk_credential_access_rule_id` FOREIGN KEY (`access_rule_id`) REFERENCES `tb_access_rule` (`id`) ON DELETE SET NULL ,
    CONSTRAINT `fk_credential_connection_id` FOREIGN KEY (`connection_id`) REFERENCES `tb_connection` (`id`) ON DELETE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

--
-- Table structure for table `tb_domain_credential`
--
CREATE TABLE IF NOT EXISTS `tb_domain_credential`
(
    `domain` VARCHAR(255)    NOT NULL,
    `id`     BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (`id`),
    CONSTRAINT `fk_domain_credential_id` FOREIGN KEY (`id`) REFERENCES `tb_credential` (`id`) ON DELETE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

--
-- Table structure for table `tb_private_key_credential`
--
CREATE TABLE IF NOT EXISTS `tb_private_key_credential`
(
    `passphrase`  VARCHAR(255) DEFAULT NULL,
    `private_kay` TEXT            NOT NULL,
    `id`          BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (`id`),
    CONSTRAINT `fk_private_key_credential_id` FOREIGN KEY (`id`) REFERENCES `tb_credential` (`id`) ON DELETE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

--
-- Table structure for table `tb_username_password_credential`
--
CREATE TABLE IF NOT EXISTS `tb_username_password_credential`
(
    `password` VARCHAR(255)    NOT NULL,
    `username` VARCHAR(255)    NOT NULL,
    `id`       BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (`id`),
    CONSTRAINT `fk_username_password_credential_id` FOREIGN KEY (`id`) REFERENCES `tb_credential` (`id`) ON DELETE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

--
-- Table structure for table `tb_session_input_constraint_violation_handler`
--
CREATE TABLE IF NOT EXISTS `tb_session_input_constraint_violation_handler`
(
    `id`                     BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `alert_someone`          BIT(1)          NOT NULL,
    `email`                  VARCHAR(254)    DEFAULT NULL,
    `log_incident`           BIT(1)          NOT NULL,
    `phone_number`           VARCHAR(32)     DEFAULT NULL,
    `prevent_execution`      BIT(1)          NOT NULL,
    `send_notification`      BIT(1)          NOT NULL,
    `terminate_session`      BIT(1)          NOT NULL,
    `access_rule_id`         BIGINT UNSIGNED DEFAULT NULL,
    `connection_id`          BIGINT UNSIGNED DEFAULT NULL,
    `constraint_id`          BIGINT UNSIGNED NOT NULL,
    `last_modifier`          VARCHAR(64)     DEFAULT NULL,
    `last_modification_time` INT UNSIGNED    DEFAULT 0,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_sicvh_constraint_id_access_rule_id` (`constraint_id`, `access_rule_id`),
    UNIQUE KEY `uk_sicvh_constraint_id_connection_id` (`constraint_id`, `connection_id`),
    KEY `fk_sicvh_access_rule_id` (`access_rule_id`),
    KEY `fk_sicvh_connection_id` (`connection_id`),
    CONSTRAINT `fk_sicvh_constraint_id` FOREIGN KEY (`constraint_id`) REFERENCES `tb_session_input_constraint` (`id`),
    CONSTRAINT `fk_sicvh_access_rule_id` FOREIGN KEY (`access_rule_id`) REFERENCES `tb_access_rule` (`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_sicvh_connection_id` FOREIGN KEY (`connection_id`) REFERENCES `tb_connection` (`id`) ON DELETE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

--
-- Table structure for table `tb_accessibility_time_period`
--
CREATE TABLE IF NOT EXISTS `tb_accessibility_time_period`
(
    `id`             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `mode`           TINYINT         NOT NULL,
    `timezone`       VARCHAR(64)     NOT NULL,
    `access_rule_id` BIGINT UNSIGNED DEFAULT NULL,
    `connection_id`  BIGINT UNSIGNED DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_accessibility_time_period_id_access_rule_id` (`id`, `access_rule_id`),
    UNIQUE KEY `uk_accessibility_time_period_id_connection_id` (`id`, `connection_id`),
    KEY `fk_accessibility_time_period_access_rule_id` (`access_rule_id`),
    KEY `fk_accessibility_time_period_connection_id` (`connection_id`),
    CONSTRAINT `fk_accessibility_time_period_access_rule_id` FOREIGN KEY (`access_rule_id`) REFERENCES `tb_access_rule` (`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_accessibility_time_period_connection_id` FOREIGN KEY (`connection_id`) REFERENCES `tb_connection` (`id`) ON DELETE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

--
-- Table structure for table `tb_daily_accessibility_time_period_constraint`
--
CREATE TABLE IF NOT EXISTS `tb_daily_accessibility_time_period_constraint`
(
    `id`             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `from_hour`      TINYINT         NOT NULL CHECK ( `from_hour` >= 0 AND `from_hour` <= 23),
    `from_minute`    TINYINT         NOT NULL CHECK ( `from_minute` >= 0 AND `from_minute` <= 59),
    `to_hour`        TINYINT         NOT NULL CHECK ( `to_hour` >= 0 AND `to_hour` <= 23),
    `to_minute`      TINYINT         NOT NULL CHECK ( `to_minute` >= 0 AND `to_minute` <= 59),
    `time_period_id` BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (`id`),
    KEY `fk_daily_accessibility_time_period_constraint_time_period_id` (`time_period_id`),
    CONSTRAINT `fk_daily_accessibility_time_period_constraint_time_period_id` FOREIGN KEY (`time_period_id`) REFERENCES `tb_accessibility_time_period` (`id`) ON DELETE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

--
-- Table structure for table `tb_weekly_accessibility_time_period_constraint`
--
CREATE TABLE IF NOT EXISTS `tb_weekly_accessibility_time_period_constraint`
(
    `id`             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `from_hour`      TINYINT         NOT NULL CHECK ( `from_hour` >= 0 AND `from_hour` <= 23),
    `from_minute`    TINYINT         NOT NULL CHECK ( `from_minute` >= 0 AND `from_minute` <= 59),
    `to_hour`        TINYINT         NOT NULL CHECK ( `to_hour` >= 0 AND `to_hour` <= 23),
    `to_minute`      TINYINT         NOT NULL CHECK ( `to_minute` >= 0 AND `to_minute` <= 59),
    `week_day`       TINYINT         NOT NULL,
    `time_period_id` BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (`id`),
    KEY `fk_weekly_accessibility_time_period_constraint_time_period_id` (`time_period_id`),
    CONSTRAINT `fk_weekly_accessibility_time_period_constraint_time_period_id` FOREIGN KEY (`time_period_id`) REFERENCES `tb_accessibility_time_period` (`id`) ON DELETE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

--
-- Table structure for table `tb_monthly_accessibility_time_period_constraint`
--
CREATE TABLE IF NOT EXISTS `tb_monthly_accessibility_time_period_constraint`
(
    `id`             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `from_hour`      TINYINT         NOT NULL CHECK ( `from_hour` >= 0 AND `from_hour` <= 23),
    `from_minute`    TINYINT         NOT NULL CHECK ( `from_minute` >= 0 AND `from_minute` <= 59),
    `to_hour`        TINYINT         NOT NULL CHECK ( `to_hour` >= 0 AND `to_hour` <= 23),
    `to_minute`      TINYINT         NOT NULL CHECK ( `to_minute` >= 0 AND `to_minute` <= 59),
    `month_day`      TINYINT         NOT NULL,
    `time_period_id` BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (`id`),
    KEY `fk_monthly_accessibility_time_period_constraint_time_period_id` (`time_period_id`),
    CONSTRAINT `fk_monthly_accessibility_time_period_constraint_time_period_id` FOREIGN KEY (`time_period_id`) REFERENCES `tb_accessibility_time_period` (`id`) ON DELETE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

--
-- Table structure for table `tb_banner`
--
CREATE TABLE IF NOT EXISTS `tb_banner`
(
    `id`             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `message`        VARCHAR(255)    NOT NULL,
    `skippable`      BIT(1)          NOT NULL,
    `access_rule_id` BIGINT UNSIGNED DEFAULT NULL,
    `connection_id`  BIGINT UNSIGNED DEFAULT NULL,
    PRIMARY KEY (`id`),
    KEY `fk_banner_access_rule_id` (`access_rule_id`),
    KEY `fk_banner_connection_id` (`connection_id`),
    CONSTRAINT `fk_banner_access_rule_id` FOREIGN KEY (`access_rule_id`) REFERENCES `tb_access_rule` (`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_banner_connection_id` FOREIGN KEY (`connection_id`) REFERENCES `tb_connection` (`id`) ON DELETE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

--
-- Table structure for table `tb_capture_rule`
--
CREATE TABLE IF NOT EXISTS `tb_capture_rule`
(
    `id`                     BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `name`                   VARCHAR(48)     NOT NULL,
    `disabled`               BIT(1)          NOT NULL,
    `expiration_time`        INT UNSIGNED DEFAULT 0,
    `export`                 BIT(1)          NOT NULL,
    `keystroke`              BIT(1)          NOT NULL,
    `creator`                VARCHAR(64)     NOT NULL,
    `creation_time`          INT UNSIGNED    NOT NULL,
    `last_modifier`          VARCHAR(64)  DEFAULT NULL,
    `last_modification_time` INT UNSIGNED DEFAULT 0,
    `description`            VARCHAR(255) DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_capture_rule_name` (`name`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

--
-- Table structure for table `tb_capture_rule_connection`
--
CREATE TABLE IF NOT EXISTS `tb_capture_rule_connection`
(
    `capture_rule_id` BIGINT UNSIGNED NOT NULL,
    `connection_id`   BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (`capture_rule_id`, `connection_id`),
    KEY `fk_capture_rule_connection_connection_id` (`connection_id`),
    CONSTRAINT `fk_capture_rule_connection_connection_id` FOREIGN KEY (`connection_id`) REFERENCES `tb_connection` (`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_capture_rule_connection_capture_rule_id` FOREIGN KEY (`capture_rule_id`) REFERENCES `tb_capture_rule` (`id`) ON DELETE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

--
-- Table structure for table `tb_capture_rule_connection_group`
--
CREATE TABLE IF NOT EXISTS `tb_capture_rule_connection_group`
(
    `capture_rule_id`     BIGINT UNSIGNED NOT NULL,
    `connection_group_id` BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (`capture_rule_id`, `connection_group_id`),
    KEY `fk_capture_rule_connection_group_connection_group_id` (`connection_group_id`),
    CONSTRAINT `fk_capture_rule_connection_group_connection_group_id` FOREIGN KEY (`connection_group_id`) REFERENCES `tb_connection_group` (`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_capture_rule_connection_group_capture_rule_id` FOREIGN KEY (`capture_rule_id`) REFERENCES `tb_capture_rule` (`id`) ON DELETE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

--
-- Table structure for table `tb_capture_rule_user`
--
CREATE TABLE IF NOT EXISTS `tb_capture_rule_user`
(
    `capture_rule_id` BIGINT UNSIGNED NOT NULL,
    `user_id`         BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (`capture_rule_id`, `user_id`),
    KEY `fk_capture_rule_user_user_id` (`user_id`),
    CONSTRAINT `fk_capture_rule_user_user_id` FOREIGN KEY (`user_id`) REFERENCES `tb_user` (`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_capture_rule_user_capture_rule_id` FOREIGN KEY (`capture_rule_id`) REFERENCES `tb_capture_rule` (`id`) ON DELETE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

--
-- Table structure for table `tb_capture_rule_user_group`
--
CREATE TABLE IF NOT EXISTS `tb_capture_rule_user_group`
(
    `capture_rule_id` BIGINT UNSIGNED NOT NULL,
    `user_group_id`   BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (`capture_rule_id`, `user_group_id`),
    KEY `fk_capture_rule_user_group_user_group_id` (`user_group_id`),
    CONSTRAINT `fk_capture_rule_user_group_user_group_id` FOREIGN KEY (`user_group_id`) REFERENCES `tb_user_group` (`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_capture_rule_user_group_capture_rule_id` FOREIGN KEY (`capture_rule_id`) REFERENCES `tb_capture_rule` (`id`) ON DELETE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

--
-- Table structure for table `tb_capture`
--
CREATE TABLE IF NOT EXISTS `tb_capture`
(
    `id`                        BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `access_rule_uuid`          VARCHAR(48)     NOT NULL,
    `session_id`                VARCHAR(48)     NOT NULL,
    `status`                    TINYINT         NOT NULL,
    `type`                      TINYINT         NOT NULL,
    `start_time`                INT             NOT NULL,
    `end_time`                  INT             NOT NULL,
    `owner`                     VARCHAR(64)     NOT NULL,
    `connection_name`           VARCHAR(48)     NOT NULL,
    `connection_ip_address`     VARCHAR(48)     NOT NULL,
    `connection_port`           INT             NOT NULL CHECK ( `connection_port` >= 1 AND `connection_port` <= 65535),
    `credential_label`          VARCHAR(48) DEFAULT NULL,
    `bridge_ip_address`         VARCHAR(48)     NOT NULL,
    `bridge_name`               VARCHAR(48)     NOT NULL,
    `active_file_transfer_mode` TINYINT         NOT NULL,
    `had_clipboard`             BIT(1)          NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_capture_session_id` (`session_id`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

--
-- Table structure for table `tb_session_captured_image`
--
CREATE TABLE IF NOT EXISTS `tb_session_captured_image`
(
    `id`         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `image_data` LONGTEXT        NOT NULL,
    `session_id` VARCHAR(48)     NOT NULL,
    PRIMARY KEY (`id`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

--
-- Table structure for table `tb_session_captured_image_text`
--
CREATE TABLE IF NOT EXISTS `tb_session_captured_image_text`
(
    `id`              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `content`         BLOB            NOT NULL,
    `image_file_name` VARCHAR(48)     NOT NULL,
    `session_id`      VARCHAR(48)     NOT NULL,
    PRIMARY KEY (`id`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

--
-- Table structure for table `tb_session_input_constraint_violation_incident`
--
CREATE TABLE IF NOT EXISTS `tb_session_input_constraint_violation_incident`
(
    `id`         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `input`      VARCHAR(255)    NOT NULL,
    `regex`      VARCHAR(255)    NOT NULL,
    `time`       INT UNSIGNED    NOT NULL,
    `capture_id` BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (`id`),
    KEY `fk_session_input_constraint_violation_incident_capture_id` (`capture_id`),
    CONSTRAINT `fk_session_input_constraint_violation_incident_capture_id` FOREIGN KEY (`capture_id`) REFERENCES `tb_capture` (`id`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

--
-- Table structure for table `tb_session_transferred_file`
--
CREATE TABLE IF NOT EXISTS `tb_session_transferred_file`
(
    `id`         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `mode`       TINYINT         NOT NULL,
    `name`       VARCHAR(255)    NOT NULL,
    `status`     TINYINT         NOT NULL,
    `time`       INT UNSIGNED    NOT NULL,
    `capture_id` BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (`id`),
    KEY `fk_session_transferred_file_capture_id` (`capture_id`),
    CONSTRAINT `fk_session_transferred_file_capture_id` FOREIGN KEY (`capture_id`) REFERENCES `tb_capture` (`id`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

--
-- Table structure for table `tb_session_timeout_setting`
--
CREATE TABLE IF NOT EXISTS `tb_session_timeout_setting`
(
    `id`                                BIGINT NOT NULL,
    `rdp_connection_timeout`            INT    NOT NULL CHECK ( `rdp_connection_timeout` >= 0 AND `rdp_connection_timeout` <= 60),
    `ssh_connection_timeout`            INT    NOT NULL CHECK ( `ssh_connection_timeout` >= 0 AND `ssh_connection_timeout` <= 60),
    `telnet_connection_timeout`         INT    NOT NULL CHECK ( `telnet_connection_timeout` >= 0 AND `telnet_connection_timeout` <= 60),
    `vnc_connection_timeout`            INT    NOT NULL CHECK ( `vnc_connection_timeout` >= 0 AND `vnc_connection_timeout` <= 60),
    `reactive_ssh_by_mouse_movement`    BIT(1) NOT NULL,
    `reactive_telnet_by_mouse_movement` BIT(1) NOT NULL,
    `last_modifier`                     VARCHAR(64)  DEFAULT NULL,
    `last_modification_time`            INT UNSIGNED DEFAULT 0,
    PRIMARY KEY (`id`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

--
-- Table structure for table `tb_symmetric_key`
--
CREATE TABLE IF NOT EXISTS `tb_symmetric_key`
(
    `id`                     BIGINT       NOT NULL,
    `symmetric_key`          VARCHAR(255) NOT NULL,
    `creator`                VARCHAR(64)  NOT NULL,
    `creation_time`          INT UNSIGNED NOT NULL,
    `last_modifier`          VARCHAR(64)  DEFAULT NULL,
    `last_modification_time` INT UNSIGNED DEFAULT 0,
    PRIMARY KEY (`id`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;


