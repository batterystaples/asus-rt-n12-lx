ROMFS_DIR = $(DIR_ROOT)/romfs
LANG_FILE = TW.dict CN.dict DE.dict EN.dict FR.dict MS.dict PL.dict RU.dict TH.dict TR.dict CZ.dict
LANGUAGE_DIR = ./language/
TARGET_DIR = "./web/"

all:$(LANG_FILE) web_downsize

%.dict: $(LANGUAGE_DIR)%.txt
	egrep '*' $^ | sed -e 's,<#ZVMODELVZ#>,$(MODEL_NAME),g' -e 's,\r,,' > $@
	mv $@ $(TARGET_DIR)

web_downsize:
	gcc -o web_downsize web_downsize.c

romfs:
	rm -Rf $(ROMFS_DIR)/web
	cp -R web $(ROMFS_DIR)/web
	rm -f $(TARGET_DIR)/*.dict
	ln -sf /tmp/config.dat $(ROMFS_DIR)/web/config.dat
	@cp -R images/$(MODEL_NAME)/*.gif $(ROMFS_DIR)/web/images
	sh comp.sh
