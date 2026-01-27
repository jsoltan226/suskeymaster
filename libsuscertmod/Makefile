# Platform and paths
PLATFORM ?= android
PREFIX ?= /usr

ifeq ($(PREFIX), /data/data/com.termux/files/usr)
TERMUX := 1
endif

NDK_TOOLCHAIN_PATH ?= /opt/android-sdk/ndk/aarch64-linux-android34

TARGET ?= $(NDK_TOOLCHAIN_PATH)/bin/aarch64-linux-android34

# Compiler and flags
CC := $(TARGET)-clang
CCLD := $(CC)
CPP := $(TARGET)-cpp
AR := $(TARGET)-ar rcs

INCLUDES ?= -I../cgd -I../external/prefix/include
ifeq ($(PLATFORM), linux)
endif

COMMON_CFLAGS := -std=gnu11 -Wall -Wextra -Wno-gnu-flexible-array-initializer -I. -pipe -fPIC $(INCLUDES)
DEPFLAGS ?= -MMD -MP

LDFLAGS ?= -pie -L../external/prefix/lib
ifeq ($(PLATFORM), windows)
LDFLAGS += -municode -mwindows
endif
SO_LDFLAGS := -shared
ifeq ($(PLATFORM), linux)
ASAN_FLAGS :=
#-fsanitize=address
#-fsanitize=thread
endif
ifeq ($(PLATFORM), windows)
ASAN_FLAGS :=
endif

LIBS ?= -lm -lcrypto
ifeq ($(TERMUX), 1)
LIBS += $(PREFIX)/lib/libandroid-shmem.a -llog
endif
ifeq ($(PLATFORM), windows)
LIBS += -lgdi32
endif
ifeq ($(PLATFORM), linux)
#LIBS += -pthread
endif

STRIP ?= strip
STRIPFLAGS ?= -g -s

# Shell commands
ECHO := echo
PRINTF := printf
RM := rm -f
TOUCH := touch -c
EXEC := exec
MKDIR := mkdir -p
RMRF := rm -rf
7Z := 7z

# Executable file Prefix/Suffix
EXEPREFIX :=
EXESUFFIX :=
ifeq ($(PLATFORM),windows)
EXESUFFIX := .exe
endif

SO_PREFIX :=
SO_SUFFIX := .so
ifeq ($(PLATFORM),windows)
SO_SUFFIX := .dll
endif

STATIC_PREFIX :=
STATIC_SUFFIX := .a
ifeq ($(PLATFORM),windows)
STATIC_SUFFIX := .lib
endif

# Directories
OBJDIR := obj
BINDIR := bin
TEST_SRC_DIR := tests
PLATFORM_SRCDIR := platform

# Test sources and objects
ifneq ($(wildcard $(TEST_SRC_DIR)),)
_use_tests := 1
endif

ifdef _use_tests
TEST_SRCS := $(wildcard $(TEST_SRC_DIR)/*.c)
TEST_BINDIR := $(TEST_SRC_DIR)/$(BINDIR)
TEST_EXES := $(patsubst $(TEST_SRC_DIR)/%.c,$(TEST_BINDIR)/$(EXEPREFIX)%$(EXESUFFIX),$(TEST_SRCS))
TEST_LOGFILE := $(TEST_SRC_DIR)/testlog.txt
endif

_static_tests_file := core/static-tests.h
ifneq ($(wildcard $(_static_tests_file)),)
_use_static_tests := 1
endif

ifdef _use_static_tests
STATIC_TESTS := $(_static_tests_file)
endif

# Sources and objects
ifneq ($(wildcard $(PLATFORM_SRCDIR)),)
_use_platform = 1
endif

ifdef _use_platform
PLATFORM_SRCS := $(wildcard $(PLATFORM_SRCDIR)/$(PLATFORM)/*.c)
PLATFORM_COMMON_SRCDIR := $(PLATFORM_SRCDIR)/common
PLATFORM_COMMON_SRCS := $(wildcard $(PLATFORM_COMMON_SRCDIR)/*.c)
endif

_all_srcs := $(wildcard */*.c) $(wildcard *.c)
SRCS := $(filter-out $(TEST_SRCS),$(_all_srcs)) $(PLATFORM_SRCS) $(PLATFORM_COMMON_SRCS)

OBJS := $(patsubst %.c,$(OBJDIR)/%.c.o,$(shell basename -a $(SRCS)))
DEPS := $(patsubst %.o,%.d,$(OBJS))

_main_obj := $(OBJDIR)/main.c.o
ifdef _use_platform
_entry_point_obj := $(OBJDIR)/entry-point.c.o
endif
ifdef _use_tests
_test_entry_point_obj := $(OBJDIR)/test-entry-point.c.o
endif

# Executables
STATIC_LIB := $(BINDIR)/$(STATIC_PREFIX)libsuscertmod$(STATIC_SUFFIX)
#EXE := $(BINDIR)/$(EXEPREFIX)main$(EXESUFFIX)
ifdef _use_tests
TEST_LIB := $(TEST_BINDIR)/$(SO_PREFIX)libmain_test$(SO_SUFFIX)
TEST_LIB_OBJS := $(filter-out $(_main_obj) $(_entry_point_obj),$(OBJS))
endif
#EXEARGS :=

.PHONY: all trace release strip clean mostlyclean update run br tests tests-release build-tests compile-tests build-tests-release compile-tests-release run-tests debug-run bdr test-hooks
.NOTPARALLEL: all trace release br bdr build-tests build-tests-release

# Build targets
all: CFLAGS = -g -O0 -Wall $(ASAN_FLAGS)
all: LDFLAGS += $(ASAN_FLAGS)
all: $(STATIC_TESTS) $(OBJDIR) $(BINDIR) $(STATIC_LIB)

trace: CFLAGS = -g -O0 -Wall -DCGD_ENABLE_TRACE $(ASAN_FLAGS)
trace: LDFLAGS += $(ASAN_FLAGS)
trace: $(STATIC_TESTS) $(OBJDIR) $(BINDIR) $(STATIC_LIB)

release: CFLAGS = -O3 -Werror -flto -DNDEBUG -DCGD_BUILDTYPE_RELEASE
release: LDFLAGS += -flto
release: $(STATIC_TESTS) clean $(OBJDIR) $(BINDIR) $(STATIC_LIB) tests-release mostlyclean strip

br: all run

# Output executable rules

$(STATIC_LIB): $(OBJS)
	@$(PRINTF) "AR  	%-30s %-30s\n" "$(STATIC_LIB)" "<= $^"
	@$(AR) $(STATIC_LIB) $(OBJS) >/dev/null

#$(EXE): $(OBJS)
#	@$(PRINTF) "CCLD 	%-30s %-30s\n" "$(EXE)" "<= $^"
#	@$(CCLD) $(LDFLAGS) -o $(EXE) $(OBJS) $(LIBS)

ifdef _use_tests
$(TEST_LIB): $(TEST_LIB_OBJS)
	@$(PRINTF) "CCLD 	%-30s %-30s\n" "$(TEST_LIB)" "<= $(TEST_LIB_OBJS)"
	@$(CCLD) $(SO_LDFLAGS) -o $(TEST_LIB) $(TEST_LIB_OBJS) $(LIBS)
endif # _use_tests

# Output directory rules
$(OBJDIR):
	@$(ECHO) "MKDIR	$(OBJDIR)"
	@$(MKDIR) $(OBJDIR)

$(BINDIR):
	@$(ECHO) "MKDIR	$(BINDIR)"
	@$(MKDIR) $(BINDIR)

$(TEST_BINDIR):
	@$(ECHO) "MKDIR	$(TEST_BINDIR)"
	@$(MKDIR) $(TEST_BINDIR)

# Generic compilation targets
$(OBJDIR)/%.c.o: %.c Makefile
	@$(PRINTF) "CC 	%-30s %-30s\n" "$@" "<= $<"
	@$(CC) $(DEPFLAGS) $(COMMON_CFLAGS) $(CFLAGS) -c -o $@ $<

$(OBJDIR)/%.c.o: */%.c Makefile
	@$(PRINTF) "CC 	%-30s %-30s\n" "$@" "<= $<"
	@$(CC) $(DEPFLAGS) $(COMMON_CFLAGS) $(CFLAGS) -c -o $@ $<

ifdef _use_platform
$(OBJDIR)/%.c.o: $(PLATFORM_SRCDIR)/$(PLATFORM)/%.c Makefile
	@$(PRINTF) "CC 	%-30s %-30s\n" "$@" "<= $<"
	@$(CC) $(DEPFLAGS) $(COMMON_CFLAGS) $(CFLAGS) -c -o $@ $<

$(OBJDIR)/%.c.o: $(PLATFORM_COMMON_SRCDIR)/%.c Makefile
	@$(PRINTF) "CC 	%-30s %-30s\n" "$@" "<= $<"
	@$(CC) $(DEPFLAGS) $(COMMON_CFLAGS) $(CFLAGS) -c -o $@ $<
endif # _use_platform

# Special compilation targets
ifdef _use_tests
ifdef _use_platform
$(_test_entry_point_obj): CFLAGS += \
	-DCGD_P_ENTRY_POINT_DEFAULT_NO_LOG_FILE=1 -DCGD_P_ENTRY_POINT_DEFAULT_VERBOSE_LOG_SETUP=0 -O0
$(_test_entry_point_obj): $(PLATFORM_SRCDIR)/$(PLATFORM)/entry-point.c Makefile $(OBJDIR)
	@$(PRINTF) "CC 	%-30s %-30s\n" "$@" "<= $<"
	@$(CC) $(DEPFLAGS) $(COMMON_CFLAGS) $(CFLAGS) -c -o $@ $<
endif # _use_platform
endif # _use_tests


ifdef _use_tests

# Test preparation targets
test-hooks:

# Test execution targets
run-tests: tests

tests: CFLAGS = -g -O0 -Wall -DCGD_ENABLE_TRACE $(ASAN_FLAGS)
tests: build-tests test-hooks
	@n_passed=0; \
	$(ECHO) -n > $(TEST_LOGFILE); \
	for i in $(TEST_EXES); do \
		$(PRINTF) "EXEC	%-30s " "$$i"; \
		if CGD_TEST_LOG_FILE="$(TEST_LOGFILE)" $$i >/dev/null 2>&1; then \
			$(PRINTF) "$(GREEN)OK$(COL_RESET)\n"; \
			n_passed="$$((n_passed + 1))"; \
		else \
			$(PRINTF) "$(RED)FAIL$(COL_RESET)\n"; \
		fi; \
	done; \
	n_total=$$(echo $(TEST_EXES) | wc -w); \
	if test "$$n_passed" -lt "$$n_total"; then \
		$(PRINTF) "$(RED)"; \
	else \
		$(PRINTF) "$(GREEN)"; \
	fi; \
	$(PRINTF) "%s/%s$(COL_RESET) tests passed.\n" "$$n_passed" "$$n_total";

# ANSI escape sequences (for printing colored text)
GREEN := \033[0;32m
RED := \033[0;31m
COL_RESET := \033[0m

tests-release: CFLAGS = -g -O0 -Wall -DCGD_ENABLE_TRACE $(ASAN_FLAGS)
tests-release: build-tests-release test-hooks
	@n_passed=0; \
	$(ECHO) -n > $(TEST_LOGFILE); \
	for i in $(TEST_EXES); do \
		$(PRINTF) "EXEC	%-30s " "$$i"; \
		if CGD_TEST_LOG_FILE="$(TEST_LOGFILE)" $$i >/dev/null 2>&1; then \
			$(PRINTF) "$(GREEN)OK$(COL_RESET)\n"; \
			n_passed="$$((n_passed + 1))"; \
		else \
			$(PRINTF) "$(RED)FAIL$(COL_RESET)\n"; \
		fi; \
	done; \
	n_total=$$(echo $(TEST_EXES) | wc -w); \
	if test "$$n_passed" -lt "$$n_total"; then \
		$(PRINTF) "$(RED)"; \
	else \
		$(PRINTF) "$(GREEN)"; \
	fi; \
	$(PRINTF) "%s/%s$(COL_RESET) tests passed.\n" "$$n_passed" "$$n_total";


# Test compilation targets
build-tests: CFLAGS = -g -O0 -Wall -DCGD_ENABLE_TRACE $(ASAN_FLAGS)
build-tests: LDFLAGS += $(ASAN_FLAGS)
build-tests: $(STATIC_TESTS) $(OBJDIR) $(BINDIR) $(TEST_BINDIR) $(TEST_LIB) $(_test_entry_point_obj) compile-tests

build-tests-release: CFLAGS = -O3 -Werror -flto -DNDEBUG -DCGD_BUILDTYPE_RELEASE
build-tests-release: LDFLAGS += -flto
build-tests-release: $(STATIC_TESTS) $(OBJDIR) $(BINDIR) $(TEST_BINDIR) $(TEST_LIB) $(_test_entry_point_obj) compile-tests-release

compile-tests: $(TEST_EXES)

compile-tests-release: $(TEST_EXES)

$(TEST_BINDIR)/$(EXEPREFIX)%$(EXESUFFIX): $(TEST_SRC_DIR)/%.c Makefile tests/log-util.h $(_test_entry_point_obj)
	@$(PRINTF) "CCLD	%-30s %-30s\n" "$@" "<= $< $(TEST_LIB) $(_test_entry_point_obj)"
	@$(CC) $(COMMON_CFLAGS) $(CFLAGS) -o $@ $< $(LDFLAGS) $(TEST_LIB) $(LIBS) $(_test_entry_point_obj)

endif # _use_tests

ifdef _use_static_tests
$(STATIC_TESTS):
	@$(CPP) $(STATIC_TESTS) >/dev/null
endif # _use_static_tests

# Cleanup targets
mostlyclean:
	@$(ECHO) "RM	$(OBJS) $(DEPS) $(TEST_LOGFILE)"
	@$(RM) $(OBJS) $(DEPS) $(TEST_LOGFILE)

clean:
	@$(ECHO) "RM	$(OBJS) $(DEPS) $(EXE) $(TEST_LIB) $(BINDIR) $(OBJDIR) $(TEST_EXES) $(TEST_BINDIR) $(TEST_LOGFILE)"
	@$(RM) $(OBJS) $(DEPS) $(EXE) $(TEST_LIB) $(TEST_EXES) $(TEST_LOGFILE) assets/tests/asset_load_test/*.png
	@$(RMRF) $(OBJDIR) $(BINDIR) $(TEST_BINDIR)

tests-clean:
	@$(ECHO) "RM	$(TEST_LIB) $(TEST_EXES) $(TEST_BINDIR) $(TEST_LOGFILE)"
	@$(RM) $(TEST_LIB) $(TEST_EXES) $(TEST_LOGFILE)
	@$(RMRF) $(TEST_BINDIR)

# Output execution targets
run:
#@$(ECHO) "EXEC	$(EXE) $(EXEARGS)"
#@$(EXEC) $(EXE) $(EXEARGS)

debug-run:
#@$(ECHO) "EXEC	$(EXE) $(EXEARGS)"
#@bash -c '$(EXEC) -a debug $(EXE) $(EXEARGS)'

bdr: all debug-run

# Miscellaneous targets
strip:
#@$(ECHO) "STRIP	$(EXE)"
#@$(STRIP) $(STRIPFLAGS) $(EXE)

update:
	@$(ECHO) "TOUCH	$(SRCS)"
	@$(TOUCH) $(SRCS)

-include $(DEPS)
