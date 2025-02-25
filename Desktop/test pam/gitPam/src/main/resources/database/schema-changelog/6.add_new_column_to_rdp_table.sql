ALTER TABLE `tb_rdp_connection`
    ADD COLUMN `enable_audio_input` BIT(1);

UPDATE `tb_rdp_connection` SET `enable_audio_input`=0;

ALTER TABLE `tb_rdp_connection`
    CHANGE COLUMN `enable_audio_input` `enable_audio_input` BIT(1) NOT NULL DEFAULT 0;