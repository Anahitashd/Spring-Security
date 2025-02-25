ALTER TABLE `tb_session_scanning_transferred_file`
    DROP COLUMN `multi_av_scanner_record_id`,
    ADD COLUMN `kavosh_request_identifier` VARCHAR(36) NOT NULL;