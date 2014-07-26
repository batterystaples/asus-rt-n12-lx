all: picsdesc.tmp
	@echo "builded"
clean:
	@echo "It's cleaned"
	@rm -rf picsdesc.tmp

picsdesc.tmp: picsdesc.skl
	egrep '*' $^ | sed -e 's,<#ZVMODELVZ#>,$(MODEL_NAME),g' -e 's,\r,,' > $@

romfs:
	$(ROMFSINST) miniigd_$(TOOLCHAIN) /bin/miniigd
	$(ROMFSINST) -s /var/linuxigd /etc/
	@mkdir -p $(DIR_ROMFS)/etc/tmp
#	@cp ./pics* $(DIR_ROMFS)/etc/tmp
	@mv ./picsdesc.tmp $(DIR_ROMFS)/etc/tmp/picsdesc.skl
