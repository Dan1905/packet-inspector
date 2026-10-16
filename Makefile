CXX      ?= c++
CXXFLAGS ?= -std=c++17 -O2 -g -Wall -Wextra -Wpedantic -Wshadow
BUILD    := build

LIB_SRCS := src/parser.cpp src/acl.cpp src/format.cpp src/stats.cpp src/pcap_file.cpp src/af_packet.cpp
LIB_OBJS := $(LIB_SRCS:%.cpp=$(BUILD)/%.o)

BIN      := $(BUILD)/packet-inspector
TEST_BIN := $(BUILD)/run-tests
GEN_BIN  := $(BUILD)/gen-sample-pcap
SAMPLE   := $(BUILD)/sample.pcap

.PHONY: all test sample demo clean

all: $(BIN) $(TEST_BIN) $(GEN_BIN)

$(BUILD)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -MMD -MP -c $< -o $@

$(BIN): $(LIB_OBJS) $(BUILD)/src/main.o
	$(CXX) $(CXXFLAGS) $^ -o $@

$(TEST_BIN): $(LIB_OBJS) $(BUILD)/tests/test_main.o
	$(CXX) $(CXXFLAGS) $^ -o $@

$(GEN_BIN): $(LIB_OBJS) $(BUILD)/tools/gen_sample_pcap.o
	$(CXX) $(CXXFLAGS) $^ -o $@

test: $(TEST_BIN)
	./$(TEST_BIN)

$(SAMPLE): $(GEN_BIN)
	./$(GEN_BIN) $@

sample: $(SAMPLE)

# Replay the generated sample traffic through the sample rules.
demo: $(BIN) $(SAMPLE)
	./$(BIN) -r $(SAMPLE) -c rules.csv

clean:
	rm -rf $(BUILD)

-include $(shell find $(BUILD) -name '*.d' 2>/dev/null)
