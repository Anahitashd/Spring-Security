DELETE
FROM `tb_session_scanning_transferred_file`;

ALTER TABLE `tb_session_scanning_transferred_file`
    MODIFY COLUMN `kavosh_request_identifier` VARCHAR(36) DEFAULT NULL,
    ADD COLUMN `registration_time` INT UNSIGNED NOT NULL,
    ADD CONSTRAINT `ck_session_scanning_transferred_file_reg_time` CHECK ( `registration_time` > 0);