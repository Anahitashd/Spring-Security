ALTER TABLE `tb_access_rule`
    ADD COLUMN `capture_disabled` BIT(1) DEFAULT 0 NOT NULL;