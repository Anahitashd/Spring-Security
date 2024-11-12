ALTER TABLE `tb_rdp_connection`
    ADD COLUMN `printer_name` VARCHAR(48);

UPDATE `tb_rdp_connection` SET `printer_name`='PAM-Printer';

ALTER TABLE `tb_rdp_connection`
    CHANGE COLUMN `printer_name` `printer_name` VARCHAR(48) NOT NULL DEFAULT 'PAM-Printer';