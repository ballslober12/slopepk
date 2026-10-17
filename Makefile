# Build either Nintendo 3DS or Nintendo DS target with devkitPro
.PHONY: all 3ds ds ps5 clean
all: 3ds

3ds:
	$(MAKE) --no-print-directory -C targets/3ds

ds:
	$(MAKE) --no-print-directory -C targets/ds

ps5:
	$(MAKE) --no-print-directory -C targets/ps5

clean:
	$(MAKE) --no-print-directory -C targets/3ds clean
	$(MAKE) --no-print-directory -C targets/ds clean
	$(MAKE) --no-print-directory -C targets/ps5 clean
