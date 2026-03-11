PREFIX := arm-none-eabi-

CC      := $(PREFIX)gcc
OBJCOPY := $(PREFIX)objcopy
OBJDUMP := $(PREFIX)objdump

BUILD := build
TARGET := $(BUILD)/payload

CPU := -mcpu=cortex-m3 -mthumb

CFLAGS := $(CPU) \
          -fPIC \
          -ffreestanding \
          -nostdlib -nostartfiles \
          -fno-stack-protector \
          -fdata-sections -ffunction-sections \
          -Os \
		  -I core -I handlers

LDFLAGS := $(CPU) \
           -T core/link.ld \
           -nostdlib -nostartfiles \
           -Wl,-N

SRCS_HANDLERS := $(wildcard handlers/*.c)
SRCS_CORE     := $(wildcard core/*.c)

OBJS := $(patsubst handlers/%.c,$(BUILD)/handlers/%.o,$(SRCS_HANDLERS)) \
        $(patsubst core/%.c,$(BUILD)/core/%.o,$(SRCS_CORE))

all: $(TARGET).bin

$(BUILD)/handlers:
	mkdir -p $@

$(BUILD)/core:
	mkdir -p $@

$(BUILD)/handlers/%.o: handlers/%.c | $(BUILD)/handlers
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/core/%.o: core/%.c | $(BUILD)/core
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET).elf: $(OBJS)
	$(CC) $(LDFLAGS) $^ -o $@

$(TARGET).bin: $(TARGET).elf
	$(OBJCOPY) -O binary $< $@

disasm:
	$(OBJDUMP) -d $(TARGET).elf

raw_disasm:
	$(OBJDUMP) -b binary -m arm -M force-thumb -D $(TARGET).bin

clean:
	rm -rf $(BUILD)

re: clean all

.PHONY: all clean disasm raw_disasm re