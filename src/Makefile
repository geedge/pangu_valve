CCC=g++

VPATH+=./cJSON
INC_PATH=-I./include -I./cJSON
CFLAGS=-Wall -g $(INC_PATH) 
LDFLAGS = 
LIBS  = -lMESA_handle_logger -lMESA_htable -lMESA_prof_load -lMESA_field_stat2 -lasmislog -lwiredcfg
LIBS += -lmaatframe
#LIBS += ./lib/libmaatframe.a
LIBS += -lrulescan -lpcre -lhiredis_vip -lssl -lcrypto -lcurl
LIBS +=-lpthread
LIBS_TEST:=$(LIBS)
LIBS += -lc3client_ok

OBJS = cJSON.o check_ip_legal.o pg_valve_consul.o pg_valve_tools.o pg_valve_stat.o pg_valve_c3.o pg_valve_deal.o pg_valve_maat.o pg_valve_main.o
OBJS_TEST= test_pg_valve.o $(OBJS)
DEPS = $(OBJS:.o=.d)

TARGET_EXE=pangu_valve
TARGET_EXE_TEST=pangu_valve_test

ALL:$(TARGET_EXE) $(TARGET_EXE_TEST)

$(TARGET_EXE):$(OBJS)
	$(CCC) $(LDFLAGS) $^ -o $@ $(LIBS)
	cp $@ ../bin/

$(TARGET_EXE_TEST):$(OBJS_TEST)
	$(CCC) $(LDFLAGS) $^ -o $@ $(LIBS_TEST)
	cp $@ ../bin/

.cpp.o:
	$(CCC) $(CFLAGS) -c $<

.c.o:
	$(CCC) $(CFLAGS) -c $<

-include $(DEPS)

clean:
	rm -rf $(OBJS_TEST) $(DEPS) $(TARGET_EXE) $(TARGET_EXE_TEST)
